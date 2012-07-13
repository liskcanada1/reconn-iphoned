#include <libusb.h>
#include <string.h>
#include <semaphore.h>
#include <malloc.h>
#include <fcntl.h>
#include <errno.h>

#include "log.h"
#include "iphoned.h"
#include "server.h"
#include "usb.h"
#include "mfi_auth.h"
#include "iap.h"

typedef enum {
	IUISTATE_INIT = 0,
	IUISTATE_DISCOVERING,
	IUISTATE_IUIOPEN,
	IUISTATE_FORCEDISCONNECT,
	IUISTATE_RXCANCELLED,
} iuistate_t;

#define IPHONE_AUTHENTICATION_TIMEOUT 105
#define USB_INTERRUPT_MRU 1024
#define MAX_NUM_IUI_REPORTS 50
#define VID_APPLE 0x5ac
#define PID_RANGE_LOW 0x1290
#define PID_RANGE_MAX 0x12af
typedef struct {
	unsigned int size;
	unsigned int id;
} tIuiReport;

static pthread_t usbloopthread;
static int terminateusbloop;
static int usblooprunning;
static int usbstartfinished = FALSE;

static pthread_t usbeventsloopthread;
static int terminateusbeventsloop;
static int usbeventsrunning;

static int iui_interfacenum = -1;
static libusb_device_handle *apple_device_handle;
static unsigned char iui_listenendpoint = 0x83;

struct libusb_transfer *rx_xfer;

static unsigned char iui_reportdescriptor[0xFF];
static tIuiReport iui_reports[MAX_NUM_IUI_REPORTS];
static int ini_maxreportsize = 0;
static int iui_maxreportid = -1;

static iuistate_t iuistate;

static int disconnectsignalfromrxthread;

static int lastconnectedstatus = FALSE;

// iphone data pipe - data IN comes from server and is meant to be encapsulated and sent to iphone app
static int toiphonepipefd[2];

// usb data pipe - data IN comes from USB rx callback thread and is meant to be handled within the main usb loop
static int usbinpipefd[2];

static int usb_is_iphone_connected();

int usb_iui_get_ideal_report_id(int pktlen) {
	int i;

	if ((pktlen + 3) > ini_maxreportsize) {
		return iui_maxreportid;
	} else {
		for (i = 0; i < MAX_NUM_IUI_REPORTS; ++i) {
			if (iui_reports[i].size >= pktlen) {
				return iui_reports[i].id;
			}
		}
	}
}

void usb_iui_send(char * iappkt, int pktlen) {
	int pktpos = 0;
	int currsz;
	int sztocopy;
	int sztozero;
	int currid;
	int res;
	int availpktspc;
	int lefttocopy;
	static unsigned char *txbuf;

	while (pktpos < pktlen) {
		lefttocopy = pktlen - pktpos;
		currid = usb_iui_get_ideal_report_id(lefttocopy + 2);
		currsz = usb_iui_get_report_size(currid);
		availpktspc = currsz - 2 + 1;
		txbuf = malloc(currsz + 1);
		txbuf[0] = currid;

		if (lefttocopy > availpktspc) {
			// fill the entire buffer.
			if (pktpos == 0) {
				txbuf[1] = 0x02;
			} else {
				txbuf[1] = 0x03;
			}
			sztocopy = availpktspc;
			sztozero = 0;
		} else {
			// partial fill of buffer
			sztocopy = lefttocopy;
			sztozero = availpktspc - sztocopy;
			if (pktpos == 0) {
				txbuf[1] = 0x00;
			} else {
				txbuf[1] = 0x01;
			}
		}

		memcpy(&(txbuf[2]), &(iappkt[pktpos]), sztocopy);
		if (sztozero != 0) {
			memset(&(txbuf[2 + sztocopy]), 0, sztozero);
		}

		uint16_t wvalue = 0x0200 | currid;

		res = libusb_control_transfer(apple_device_handle,
				LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE, 9,
				wvalue, iui_interfacenum, txbuf, currsz + 1, 1000);
		iphoned_log(IPHONEDLOG_SPEW,
				"libusb_control_transfer fullsz %d used %d", currsz + 1,
				sztocopy);
		pktpos += sztocopy;
		free(txbuf);
	}
}

int parse_hid_into_iui_ints(unsigned char * descriptor, int descriptorsz) {
	int reportidx = 0;
	int descriptoridx = 0;
	int size;
	int type;
	int tag;
	int ininput = FALSE;

	memset(iui_reports, 0, sizeof(iui_reports));
	while (descriptoridx < descriptorsz) {
		size = descriptor[descriptoridx] & 0x03;
		type = (descriptor[descriptoridx] >> 2) & 3;
		tag = (descriptor[descriptoridx] >> 4) & 15;

		if ((type == 0) && (tag == 8)) {
			ininput = TRUE;
		}
		if (ininput == TRUE) {

			if ((type == 1) && (tag == 8)) {
				iui_reports[reportidx].id = descriptor[descriptoridx + 1]; // TODO:  generalize for size
			}
			if ((type == 1) && (tag == 9)) {
				iui_reports[reportidx].size = descriptor[descriptoridx + 1];
				if (size == 2) {
					iui_reports[reportidx].size = iui_reports[reportidx].size
							+ (descriptor[descriptoridx + 2] * 0x100);
				}
				if (iui_reports[reportidx].size >= ini_maxreportsize) {
					ini_maxreportsize = iui_reports[reportidx].size;
					iui_maxreportid = iui_reports[reportidx].id;
				}
				iphoned_log(IPHONEDLOG_SPEW, "IUI report id:%d size:%d",
						iui_reports[reportidx].id, iui_reports[reportidx].size);
				ininput = FALSE;
				++reportidx;
			}

		}
		descriptoridx += 1 + size;
	}
}

static int usb_is_iphone_connected() {
	libusb_device **devs;
	int i;
	int cnt;
	int retval = FALSE;

	cnt = libusb_get_device_list(NULL, &devs);
	if (cnt < 0) {
		iphoned_log(IPHONEDLOG_ERROR, "libusb_get_device_list error");
		return -1;
	}
	for (i = 0; i < cnt; ++i) {
		libusb_device *dev = devs[i];
		if (usb_is_apple_device(dev) == TRUE) {
			retval = TRUE;
		}
	}
	libusb_free_device_list(devs, 0);
	return retval;
}

int usb_connect_iphone() {
	int res;
	int cnt;
	int i;
	libusb_device **devs;
	int found = FALSE;
	libusb_device *dev;

	cnt = libusb_get_device_list(NULL, &devs);
	if (cnt < 0) {
		iphoned_log(IPHONEDLOG_ERROR, "libusb_get_device_list error");
		return -1;
	}
	iphoned_log(IPHONEDLOG_SPEW, "libusb_get_device_list found %d devices",
			cnt);

	for (i = 0; i < cnt; ++i) {
		dev = devs[i];
		found = FALSE;
		if (usb_is_apple_device(dev) == TRUE) {
			found = TRUE;
			break;
		}
	}
	libusb_free_device_list(devs, 0);
	if (found == FALSE) {
		return 0;
	}
	iui_interfacenum = usb_get_iui_interface_num(dev);
	res = libusb_open(dev, &apple_device_handle);
	if (res != 0) {
		iphoned_log(IPHONEDLOG_WARNING, "libusb_open fail %d", res);
		return -1;
	}
	if (iui_interfacenum < 0) {
		// we're not at the right configuration - need to set it here
		res = usb_set_iui_configuration(apple_device_handle);
		if (res != 0) {
			libusb_close(apple_device_handle);
			apple_device_handle = NULL;
			iphoned_log(IPHONEDLOG_WARNING, "error setting iui configuration",
					cnt);
			return -1;
		}
		iui_interfacenum = usb_get_iui_interface_num(dev);
		if (iui_interfacenum < 0) {
			libusb_close(apple_device_handle);
			apple_device_handle = NULL;
			iphoned_log(IPHONEDLOG_WARNING,
					"failed to locate iui interface on device");
			return -1;
		}
		// we have the iui interface number.
	}
	iphoned_log(IPHONEDLOG_INFO, "iuiinterfacenum %d", (int) iui_interfacenum);

	res = libusb_kernel_driver_active(apple_device_handle, iui_interfacenum);
	if (res != 0) {
		res = libusb_detach_kernel_driver(apple_device_handle,
				iui_interfacenum);
		if ((res != 0) && (res != LIBUSB_ERROR_NOT_FOUND)) {
			libusb_close(apple_device_handle);
			apple_device_handle = NULL;
			iphoned_log(IPHONEDLOG_WARNING,
					"libusb_detach_kernel_driver fail %d", res);
			return -1;
		}
	}

	iphoned_log(IPHONEDLOG_INFO, "--------------1");
	res = libusb_claim_interface(apple_device_handle, iui_interfacenum);
	if (res != 0) {
		libusb_close(apple_device_handle);
		apple_device_handle = NULL;
		iphoned_log(IPHONEDLOG_WARNING, "libusb_claim_interface fail %d", res);
		return -1;
	}
	iphoned_log(IPHONEDLOG_INFO, "--------------2");
	res = libusb_control_transfer(apple_device_handle,
			LIBUSB_ENDPOINT_IN | LIBUSB_RECIPIENT_INTERFACE, 6, 0x2200, 2,
			iui_reportdescriptor, 0xd0, 1000);
	iphoned_log(IPHONEDLOG_INFO, "--------------3");
	if (res > 0) {
		iphoned_log(IPHONEDLOG_WARNING, "got HID report descriptor %d",
				(int) res);
	} else {
		iphoned_log(IPHONEDLOG_WARNING,
				"failed to get HID report descriptor %d", (int) res);
		libusb_release_interface(apple_device_handle, iui_interfacenum);
		libusb_close(apple_device_handle);
		apple_device_handle = NULL;
		return -1;
	}
	iphoned_log(IPHONEDLOG_INFO, "--------------4");
	parse_hid_into_iui_ints(iui_reportdescriptor, res);
	iphoned_log(IPHONEDLOG_INFO, "iphone discovered");
	return 1;
}

int usb_set_iui_configuration(libusb_device_handle *handle) {
	int res;

	if (handle != NULL) {
		if ((res = libusb_set_configuration(handle, 2)) != 0) {
			iphoned_log(IPHONEDLOG_ERROR, "libusb_set_configuration fail %d",
					res);
			usb_disconnected();
			return -1;
		}
	} else {
		return -1;
	}
	return 0;
}

int usb_is_apple_device(libusb_device *dev) {
	int res;
	struct libusb_device_descriptor devdesc;
	uint8_t bus = libusb_get_bus_number(dev);
	uint8_t address = libusb_get_device_address(dev);

	if ((res = libusb_get_device_descriptor(dev, &devdesc)) != 0) {
		iphoned_log(IPHONEDLOG_ERROR,
				"Could not get device descriptor for device %d-%d: %d", bus,
				address, res);
		usb_disconnected();
		return FALSE;
	}

	if (devdesc.idVendor != VID_APPLE) {
		return FALSE;
	}
	if ((devdesc.idProduct < PID_RANGE_LOW)
			|| (devdesc.idProduct > PID_RANGE_MAX)) {
		return FALSE;
	}
	iphoned_log(IPHONEDLOG_INFO,
			"Found iphone with product info %04x:%04x USB %d-%d",
			devdesc.idVendor, devdesc.idProduct, bus, address);
	return TRUE;
}

int usb_get_iui_interface_num(libusb_device *dev) {
	struct libusb_config_descriptor *config;
	int i;
	int res;

	if ((res = libusb_get_active_config_descriptor(dev, &config)) != 0) {
		iphoned_log(IPHONEDLOG_ERROR,
				"libusb_get_active_config_descriptor fail %d", res);
		usb_disconnected();
		return -1;
	}
	for (i = 0; i < config->bNumInterfaces; ++i) {
		const struct libusb_interface_descriptor *intf =
				&config->interface[i].altsetting[0];
		if (intf->bInterfaceClass == 3 && intf->bInterfaceSubClass == 0
				&& intf->bInterfaceProtocol == 0) {
			iphoned_log(IPHONEDLOG_INFO, "iUI device found interface %d", i);
			return i;
		}
	}
	return -1;
}

int usb_iui_get_report_size(int report_id) {
	int i;
	int retval = -1;
	for (i = 0; i < MAX_NUM_IUI_REPORTS; ++i) {
		if (report_id == iui_reports[i].id) {
			retval = iui_reports[i].size;
		}
	}
	return retval;
}

int usb_force_disconnect() {
	int res;

	iphoned_log(IPHONEDLOG_INFO, "usb_force_disconnect");
	if (apple_device_handle != NULL) {
		libusb_release_interface(apple_device_handle, iui_interfacenum);
		libusb_close(apple_device_handle);
	}
	apple_device_handle = NULL;
}

int usb_disconnected() {
	iphoned_log(IPHONEDLOG_INFO, "usb_disconnected");
	disconnectsignalfromrxthread = TRUE;
}

void *usbeventsloop(void *ptr) {
	int res;
	struct timeval tv;

	usbeventsrunning = TRUE;
	while (terminateusbeventsloop == FALSE) {
		tv.tv_sec = 1;
		res = libusb_handle_events_timeout(NULL, &tv);
		if (res != 0) {
			iphoned_log(IPHONEDLOG_ERROR, "libusb_handle_events failed: %d",
					res);
			break;
		}
	}
	usbeventsrunning = FALSE;
}

void usb_loop_wait_for_events(int timeoutms) {
	int maxfd;
	int res;
	fd_set usbinpipeset;
	fd_set toiphonepipeset;
	unsigned char *iphonedatabuf;
	struct timeval timeout;
	unsigned char *buf;
	int len;
	int max_data_sz = iap_get_max_data_sz();

	len = 0;
	FD_ZERO(&usbinpipeset); /* clear the set */
	FD_SET(usbinpipefd[0], &usbinpipeset); /* add our file descriptor to the set */
	FD_SET(toiphonepipefd[0], &usbinpipeset);
	if (usbinpipefd[0] > toiphonepipefd[0]) {
		maxfd = usbinpipefd[0];
	} else {
		maxfd = toiphonepipefd[0];
	}
	timeout.tv_sec = 0;
	timeout.tv_usec = timeoutms * 1000;
	res = select(maxfd + 1, &usbinpipeset, NULL, NULL, &timeout);
	if (res == -1) {
	} else if (res == 0) {
	} else {
		// read from the USB data pipe
		if (FD_ISSET(usbinpipefd[0], &usbinpipeset)) {
			buf = (unsigned char *) malloc(1024);
			res = read(usbinpipefd[0], buf, 1024);
			iphoned_log(IPHONEDLOG_ERROR, "usb rx2 %d %d", res, iuistate);
			if (iuistate == IUISTATE_IUIOPEN) {
				if (res > 0) {
					iap_parsestream(buf, res);
				}
			}
			free(buf);
		}

		// Read from the iphone data pipe
		if (FD_ISSET(toiphonepipefd[0], &usbinpipeset)) {
			// wait until we've received some data from the USB before processing more from the server pipe
			if (iap_isreadyfordata() == TRUE) {
				iphonedatabuf = malloc(max_data_sz);
				res = read(toiphonepipefd[0], iphonedatabuf, max_data_sz);
				if (res > 0) {
					iap_presentdatafortransfer(iphonedatabuf, res);
				}
				free(iphonedatabuf);
			}
			if (iuistate != IUISTATE_IUIOPEN) {
				// flush
				iphonedatabuf = malloc(max_data_sz);
				res = read(toiphonepipefd[0], iphonedatabuf, max_data_sz);
				free(iphonedatabuf);
			}
		}
	}
}

void *usb_loop(void *ptr) {
	int res;
	int connstatus;

	usblooprunning = TRUE;
	while (1) {
		switch (iuistate) {
		case IUISTATE_INIT:
			if (terminateusbloop == TRUE) {
				usblooprunning = FALSE;
				return 0;
			}
			iuistate = IUISTATE_DISCOVERING;
			break;
		case IUISTATE_DISCOVERING:
			if (terminateusbloop == TRUE) {
				usblooprunning = FALSE;
				return 0;
			}
			res = usb_connect_iphone();
			if (res > 0) {
				disconnectsignalfromrxthread = FALSE;
				iuistate = IUISTATE_IUIOPEN;
				iap_reset_connection();
				res = usb_start_iphonemonitor();
				if (res != 0) {
					iphoned_log(IPHONEDLOG_ERROR,
							"failed to create iphone monitor thread");
					iuistate = IUISTATE_RXCANCELLED;
				}
			} else if (res < 0) {
				iphoned_log(IPHONEDLOG_ERROR, "usb_connect_iphone fail %d", res);
				sleep(1);
			} else {
				sleep(1);
			}
			break;
		case IUISTATE_IUIOPEN:
			if ((disconnectsignalfromrxthread == TRUE)
					|| (terminateusbloop == TRUE)) {
				iuistate = IUISTATE_FORCEDISCONNECT;
			} else {
				int i = 5;
				while ((iap_process_state() == TRUE) && (i-- > 0)) {
					; // keep executing while there is work to do
				}
			}
			break;
		case IUISTATE_FORCEDISCONNECT:
			if (rx_xfer != NULL) {
				libusb_cancel_transfer(rx_xfer);
			} else {
				iuistate = IUISTATE_RXCANCELLED;
			}
			break;
		case IUISTATE_RXCANCELLED:
			usb_force_disconnect();
			iuistate = IUISTATE_DISCOVERING;
			if (terminateusbloop == TRUE) {
				usblooprunning = FALSE;
				return 0;
			}
			break;
		}

		// check the connection status and report
		connstatus = iap_isappsessionopen();
		if (iuistate != IUISTATE_IUIOPEN) {
			connstatus = FALSE;
		}
		if (connstatus != lastconnectedstatus) {
			server_report_iphone_connect(connstatus);
			lastconnectedstatus = connstatus;
		}

		// pend on the two file pipes
		if (iap_is_pending_action() == TRUE) {
			usb_loop_wait_for_events(1);
		} else {
			usb_loop_wait_for_events(1000);
		}
	}
}

int usb_isiphonepresent() {
	return iap_isappsessionopen();
}

static void usb_rx_callback(struct libusb_transfer *xfer) {
	if (xfer->status == LIBUSB_TRANSFER_COMPLETED) {
		write(usbinpipefd[1], xfer->buffer, xfer->actual_length);
		libusb_submit_transfer(xfer);
	} else {
		switch (xfer->status) {
		case LIBUSB_TRANSFER_ERROR:
			// funny, this happens when we disconnect the device while waiting for a transfer, sometimes
			iphoned_log(IPHONEDLOG_ERROR,
					"rx loop aborted due to error or disconnect");
			break;
		case LIBUSB_TRANSFER_TIMED_OUT:
			iphoned_log(IPHONEDLOG_ERROR, "RX loop timed out");
			break;
		case LIBUSB_TRANSFER_CANCELLED:
			iphoned_log(IPHONEDLOG_ERROR, "rx loop cancelled");
			break;
		case LIBUSB_TRANSFER_STALL:
			iphoned_log(IPHONEDLOG_ERROR, "rx loop stalled");
			break;
		case LIBUSB_TRANSFER_NO_DEVICE:
			// other times, this happens, and also even when we abort the transfer after device removal
			iphoned_log(IPHONEDLOG_ERROR, "rx loop aborted - disconnected");
			break;
		case LIBUSB_TRANSFER_OVERFLOW:
			iphoned_log(IPHONEDLOG_ERROR, "rx overflow");
			break;
			// and nothing happens (this never gets called) if the device is freed after a disconnect! (bad)
		}
		libusb_free_transfer(xfer);
		rx_xfer = NULL;
		usb_disconnected();
		iuistate = IUISTATE_RXCANCELLED;
	}
}

int usb_start_iphonemonitor(void) {

	int res;
	void *buf;
	static unsigned char rx_buf[USB_INTERRUPT_MRU];

	rx_xfer = libusb_alloc_transfer(0);
	libusb_fill_interrupt_transfer(rx_xfer, apple_device_handle,
			iui_listenendpoint, rx_buf, USB_INTERRUPT_MRU, usb_rx_callback, 0,
			0);
	res = libusb_submit_transfer(rx_xfer);
	iphoned_log(IPHONEDLOG_ERROR, "libusb_submit_transfer %d", res);
	if (res != 0) {
		libusb_free_transfer(rx_xfer);
		rx_xfer = NULL;
		iphoned_log(IPHONEDLOG_ERROR, "libusb_submit_transfer fail %d", res);
		return -1;
	}
	return 0;
}

int usb_mfiauth_fetch_auth_info(void) {
	int res;
	unsigned char len[2];
	int reallen;
	unsigned char deviceidbuf[4];
	int deviceid;
	static unsigned char auth_cert[AUTH_CERT_MAX_SZ];
	static int cert_len;

	res = libusb_init(NULL);
	if (res != 0) {
		iphoned_log(IPHONEDLOG_ERROR, "libusb initialization failed %d", res);
		return -1;
	}

	res = mfi_auth_init();
	if (res != 0) {
		iphoned_log(IPHONEDLOG_ERROR, "mfi_auth_init fail %d", res);
		return res;
	}

	res = mfi_auth_get_cert_and_length(auth_cert, &cert_len);
	if (res != 0) {
		iphoned_log(IPHONEDLOG_ERROR, "mfi_auth_get_cert_and_length fail %d",
				res);
	}

	res = mfi_auth_get_device_id(&deviceid);
	if (res != 0) {
		iphoned_log(IPHONEDLOG_ERROR, "mfi_auth_get_device_id fail %d", res);
	}
	iap_setDeviceID(deviceid);
	iap_setcertificate(auth_cert, cert_len);

	iphoned_log(IPHONEDLOG_INFO,
			"MFI fetch complete:  device ID: %x  certificate length: %d",
			deviceid, cert_len);
	return 0;
}

int usb_start() {
	int res;
	int flags;

	iuistate = IUISTATE_INIT;

	res = usb_mfiauth_fetch_auth_info();
	if (res != 0) {
		iphoned_log(IPHONEDLOG_ERROR, "usb_fetch_auth_info fail %d", res);
		FATAL(0);
	}

	if (pipe(toiphonepipefd) == -1) {
		iphoned_log(IPHONEDLOG_ERROR, "failed to get pipe %d", res);
		FATAL(0);
	}
	if (pipe(usbinpipefd) == -1) {
		iphoned_log(IPHONEDLOG_ERROR, "failed to get pipe %d", res);
		FATAL(0);
	}

	if (res != 0) {
		iphoned_log(IPHONEDLOG_ERROR, "USB subsystem init failed. %d", res);
		FATAL(0);
	}
	terminateusbloop = FALSE;

	res = pthread_create(&usbloopthread, NULL, usb_loop, (void*) "usbloop");
	if (res != 0) {
		iphoned_log(IPHONEDLOG_ERROR, "failed to create usb discover thread");
		FATAL(0);
	}
	terminateusbeventsloop = FALSE;
	res = pthread_create(&usbeventsloopthread, NULL, usbeventsloop,
			(void*) "usbeventsloop");
	if (res != 0) {
		iphoned_log(IPHONEDLOG_ERROR, "failed to create usb events thread");
		FATAL(0);
	}
	usbstartfinished = TRUE;
	return 0;
}

void usb_stop(void) {

	iphoned_log(IPHONEDLOG_INFO, "usb_stop");

	// wait for start to be done
	while (usbstartfinished == FALSE) {
		usleep(10000);
	}

	iphoned_log(IPHONEDLOG_INFO, "usb_stop2");
	mfi_auth_close();

	iphoned_log(IPHONEDLOG_INFO, "usb_stop3");
	terminateusbloop = TRUE;
	while (usblooprunning == TRUE) {
		usleep(10000);
	}

	iphoned_log(IPHONEDLOG_INFO, "usb_stop4");
	terminateusbeventsloop = TRUE;
	while (usbeventsrunning == TRUE) {
		usleep(10000);
	}
	iphoned_log(IPHONEDLOG_INFO, "usb_stop5");
	libusb_exit(NULL);

	close(toiphonepipefd[0]);
	close(toiphonepipefd[1]);
	close(usbinpipefd[0]);
	close(usbinpipefd[1]);
	iphoned_log(IPHONEDLOG_INFO, "usb_stopped");
}

void usb_forward_iphone_data(unsigned char *buf, int len) {
// queue data to be forwarded to iphone
	write(toiphonepipefd[1], buf, len);
}

