//******************************************************************************
//******************************************************************************
//
// FILE:        mfi_auth.c
//
// DESCRIPTION: contains library functions to interface with iphoned
//
//******************************************************************************
//
//                       CONFIDENTIALITY NOTICE:
//
// THIS FILE CONTAINS MATERIAL THAT IS "HARRIS PROPRIETARY INFORMATION"  ANY
// REVIEW, RELIANCE, DISTRIBUTION, DISCLOSURE, OR FORWARDING WITHOUT EXPRESSED
// PERMISSION IS STRICTLY PROHIBITED.  PLEASE BE SURE TO PROPERLY DISPOSE ANY
// HARDCOPIES OF THIS DOCUMENT.
//
//******************************************************************************
//
// Government Use Rights:
//
//           (Applicable only for source code delivered under U. S.
//           Government contracts)
//
//                           RESTRICTED RIGHTS LEGEND
//           Use, duplication, or disclosure is subject to restrictions
//           stated in the Government's contract with Harris Corporation,
//           RF Communications Division. The applicable contract number is
//           indicated on the media containing this software. As a minimum,
//           the Government has restricted rights in the software as
//           defined in DFARS 252.227-7013.
//
// Commercial Use Rights:
//
//           (Applicable only for source code procured under contracts other
//           than with the U. S. Government)
//
//                           TRADE SECRET
//           Contains proprietary information of Harris Corporation.
//
// Copyright:
//           Protected as an unpublished copyright work,
//                    (c) Harris Corporation
//           First fixed in 2012, all rights reserved.
//
//******************************************************************************
//
// HISTORY: Created <MM>/<DD>/<YYYY> by <USER>
// $Header:$
// $Revision: $
// $Log:$
//
//******************************************************************************
//******************************************************************************
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <memory.h>
#include <sys/mman.h>
#include <errno.h>
#include <linux/i2c-dev.h>

#include "mfi_auth.h"
#include "log.h"
#include "iphoned.h"

/**
 * Coprocessor Register Addresses
 */
#define MFI_AUTH_COP_REG_ADDR_DEVICE_VERSION            0x00
#define MFI_AUTH_COP_REG_ADDR_FIRMWARE_VERSION          0x01
#define MFI_AUTH_COP_REG_ADDR_AUTH_PROT_MAJOR_VERS      0x02
#define MFI_AUTH_COP_REG_ADDR_AUTH_PROT_MINOR_VERS      0x03
#define MFI_AUTH_COP_REG_ADDR_DEV_ID                    0x04
#define MFI_AUTH_COP_REG_ADDR_ERR_CODE                  0x05
#define MFI_AUTH_COP_REG_ADDR_AUTH_CTRL_AND_STATUS      0x10
#define MFI_AUTH_COP_REG_ADDR_SIGNATURE_LEN             0x11
#define MFI_AUTH_COP_REG_ADDR_SIGNATURE_DATA            0x12
#define MFI_AUTH_COP_REG_ADDR_CHALLENGE_LEN             0x20
#define MFI_AUTH_COP_REG_ADDR_CHALLENGE_DATA            0x21
#define MFI_AUTH_COP_REG_ADDR_ACC_CERT_LEN              0x30
#define MFI_AUTH_COP_REG_ADDR_ACC_CERT_DATA_BASE        0x31
#define MFI_AUTH_COP_REG_ADDR_SELF_TEST                 0x40
#define MFI_AUTH_COP_REG_ADDR_SEC                       0x4d
#define MFI_AUTH_COP_REG_ADDR_IPOD_CERT_LEN             0x50
#define MFI_AUTH_COP_REG_ADDR_IPOD_CERT_DATA_BASE       0x51

#define NRESET_GPIO     175
#define MODE_0_GPIO     0
#define MODE_1_GPIO     56

#define MAX_MFI_TIMEOUT 50

#define MFI_AUTH_I2C_RETRY_COUNT        10
#define MFI_AUTH_I2C_RETRY_DELAY_US     1000

#define MFI_AUTH_SLAVE_ADDR 0x20

#define I2C_DEV_FILE_PATH "/dev/i2c-2"

static int i2cfd = -1;

static int mfi_auth_openi2c_fd(void);
static int mfi_auth_setupgpio(void);
static int mfi_auth_i2c_write_reg(unsigned char reg, unsigned char *pbuf,
		size_t count);
static int mfi_auth_i2c_read_reg(unsigned char reg, unsigned char *pbuf,
		size_t count);

/**
 * opens the MFI authentication coprocessor i2c file descriptor for use
 *
 * attempts to open a file descriptor for the predefined i2c device and save it to
 * a global variable.
 *
 * @return 0 is successful, a negative number if not
 */
static int mfi_auth_openi2c_fd(void) {
	int res;

	i2cfd = open(I2C_DEV_FILE_PATH, O_RDWR);
	if (i2cfd < 0) {
		iphoned_log(IPHONEDLOG_ERROR, "open i2c fd fail %d %d", i2cfd, errno);
		return -1;
	}

	/**
	 * Change slave address. The address is passed in the 7 lower bits of the
	 * argument (except for 10 bit addresses, passed in the 10 lower bits in
	 * this case).
	 */
	res = ioctl(i2cfd, I2C_SLAVE, (MFI_AUTH_SLAVE_ADDR) >> 1);
	if (res < 0) {

		iphoned_log(IPHONEDLOG_ERROR, "ioctl slave setup fail %d %d", res,
				errno);
		close(i2cfd);
		return res;
	}
	return 0;
}

/**
 * initializes the mfi_auth module for use
 *
 * performs required initialization steps to enable communication with the MFI
 * authentication coprocessor.
 *
 * @return 0 is successful, a nonzero number if not
 */
int mfi_auth_init(void) {
	int res;

	res = mfi_auth_setupgpio();
	if (res != 0) {
		iphoned_log(IPHONEDLOG_ERROR, "mfi_auth_setupgpio fail %d", res);
		return res;
	}
	res = mfi_auth_openi2c_fd();
	if (res != 0) {
		iphoned_log(IPHONEDLOG_ERROR, "mfi_auth_setupgpio fail %d", res);
		return res;
	}
}

/**
 * closes the mfi auth module
 *
 * performs cleanup on mfi_auth module to close
 */
void mfi_auth_close(void) {
	if (i2cfd >= 0) {
		close(i2cfd);
	}
}

/**
 * uses GPIO to set mode and perform a soft reset of the MFI auth coprocessor
 *
 * sets up GPIO direction and uses GPIO as follows:
 *
 * 1.  assert RESET
 * 2.  bring MODE0/MODE1 to configure i2c configuration
 * 3.  de-assert RESET
 * 4.  wait
 *
 * @return 0 is successful, a nonzero number if not
 */
static int mfi_auth_setupgpio(void) {
	FILE *fp;
	char buf[256];

	snprintf(buf, sizeof(buf), "/sys/class/gpio/gpio%d/direction", NRESET_GPIO);
	fp = fopen(buf, "wt");
	if (!fp) {
		return -1;
	}
	fputs("out", fp);
	fclose(fp);

	snprintf(buf, sizeof(buf), "/sys/class/gpio/gpio%d/value", NRESET_GPIO);
	fp = fopen(buf, "wt");
	if (!fp) {
		return -1;
	}
	fputs("0", fp);
	fclose(fp);

	snprintf(buf, sizeof(buf), "/sys/class/gpio/gpio%d/direction", MODE_1_GPIO);
	fp = fopen(buf, "wt");
	if (!fp) {
		return -1;
	}
	fputs("out", fp);
	fclose(fp);

	snprintf(buf, sizeof(buf), "/sys/class/gpio/gpio%d/value", MODE_1_GPIO);
	fp = fopen(buf, "wt");
	if (!fp) {
		return -1;
	}
	fputs("0", fp);
	fclose(fp);

	// reset chip
	usleep(100000); // sleep for 100 milliseconds

	snprintf(buf, sizeof(buf), "/sys/class/gpio/gpio%d/value", MODE_1_GPIO);
	fp = fopen(buf, "wt");
	if (!fp) {
		return -1;
	}
	fputs("1", fp);
	fclose(fp);

	usleep(10000); // sleep for 10 milliseconds

	snprintf(buf, sizeof(buf), "/sys/class/gpio/gpio%d/value", NRESET_GPIO);
	fp = fopen(buf, "wt");
	if (!fp) {
		return -1;
	}
	fputs("1", fp);
	fclose(fp);
	usleep(50000); // sleep for 50 milliseconds

	return 0;
}

/**
 * performs a common i2c read with register ID with retry
 *
 * performs a common i2c read by first writing the register ID to the i2c device,
 * then reading the specified number of bytes from a register.  i2c read/write may
 * fail if device is busy, so retries are used.
 *
 * @param reg:  register address to read from
 * @param pbuf:  buffer to place read data in
 * @param count:  number of bytes to read
 *
 * @return 0 is successful, -1 if not
 */
static int mfi_auth_i2c_read_reg(unsigned char reg, unsigned char *pbuf,
		size_t count) {
	int ret;
	int retry;
	int status;

	// write the register address to read
	for (retry = MFI_AUTH_I2C_RETRY_COUNT;; retry--) {
		ret = write(i2cfd, &reg, sizeof(reg));
		if (ret == sizeof(reg)) {
			break;
		} else if (!retry) {
			return -1;
		} else
		{
			usleep(MFI_AUTH_I2C_RETRY_DELAY_US);
		}
	}
	if (retry) {
		// no timeout. now read the register's contents
		for (retry = MFI_AUTH_I2C_RETRY_COUNT;; retry--) {
			ret = read(i2cfd, pbuf, count);
			if (ret == count) {
				break;
			} else if (!retry) {
				status = -1;
				break;
			} else
			{
				usleep(MFI_AUTH_I2C_RETRY_DELAY_US);
			}
		}
	}
	if (retry) {
		status = 0;
	} else {
		// timeout
		status = -1;
	}
	return status;
}

/**
 * performs a common i2c write with register ID with retry
 *
 * performs a common i2c read by first writing the register ID to the i2c device,
 * then reading the specified number of bytes from a register.  i2c read/write may
 * fail if device is busy, so retries are used.
 *
 * @param reg:  register address to write to
 * @param pbuf:  buffer to place write data to
 * @param count:  number of bytes to write
 *
 * @return 0 is successful, -1 if not
 */
static int mfi_auth_i2c_write_reg(unsigned char reg, unsigned char *pbuf,
		size_t count) {
	int ret;
	int retry;
	int status;
	unsigned char *p;

//	 The steps we need to perform are:
//	 1. send the i2c start sequence
//	 2. send the i2c write address
//	 3. check for ack
//	 4. send the register address
//	 5. send the data bytes
//	 6. send the i2c stop sequence


//	 since we have to send the register address AND data bytes
//	 w/o an intervening possible i2c stop sequence, we have to create
//	 a buffer, concatenate the register address AND data buffer into
//	 it, transmit it then free the buffer

	p = malloc(count + sizeof(reg));
	if (!p) {
		return -1;
	}
	p[0] = reg;
	memcpy(&p[0], &reg, sizeof(reg));
	memcpy(&p[sizeof(reg)], pbuf, count);
	count += sizeof(reg);

	// now write the buffer to the register
	for (retry = MFI_AUTH_I2C_RETRY_COUNT;; retry--) {
		ret = write(i2cfd, p, count);
		if (ret == count) {
			break;
		} else if (!retry) {
			iphoned_log(IPHONEDLOG_ERROR,
					"write(%d, %p, %d) failed, ret:%d errno:%d\n", i2cfd, pbuf,
					count, ret, errno);
			status = -1;
			break;
		} else
		{
			usleep(MFI_AUTH_I2C_RETRY_DELAY_US);
		}
	}
	if (retry) {
		status = 0;
	} else {
		// timeout
		status = -1;
	}

	free(p);

	return status;
}

/**
 * fetches MFI coprocessor certificate and certificate length
 *
 * uses the authentication coprocessor I/O routines to fetch certificate and length
 * and places the data in the provided buffers
 *
 * @param buf:  pointer to buffer to write certificate to
 * @param len:  integer location to write certificate length to
 *
 * @return 0 is successful, nonzero if not
 */
int mfi_auth_get_cert_and_length(unsigned char *buf, unsigned int *len) {
	unsigned char lenbuf[2];
	int res;

	// read the certificate length
	res = mfi_auth_i2c_read_reg(MFI_AUTH_COP_REG_ADDR_ACC_CERT_LEN, lenbuf, 2);
	if (res != 0) {
		iphoned_log(IPHONEDLOG_ERROR,
				"MFI_AUTH_COP_REG_ADDR_ACC_CERT_LEN fail %d", res);
		return res;
	}
	*len = (lenbuf[0] * 256) + lenbuf[1];

	// read the certificate buffer
	res = mfi_auth_i2c_read_reg(MFI_AUTH_COP_REG_ADDR_ACC_CERT_DATA_BASE, buf,
			AUTH_CERT_MAX_SZ);
	if (res != 0) {
		iphoned_log(IPHONEDLOG_ERROR,
				"MFI_AUTH_COP_REG_ADDR_ACC_CERT_DATA_BASE fail %d", res);
		return res;
	}
	return 0;
}

/**
 * fetches MFI authentication device ID
 *
 * fetches MFI authentication device ID and writes to specified location
 *
 * @param deviceid:  integer location to write device ID to
 *
 * @return 0 is successful, nonzero if not
 */
int mfi_auth_get_device_id(unsigned int *deviceid) {
	unsigned char deviceidbuf[4];
	int res;

	// read the device ID
	res = mfi_auth_i2c_read_reg(MFI_AUTH_COP_REG_ADDR_DEV_ID, deviceidbuf, 4);
	if (res != 0) {
		iphoned_log(IPHONEDLOG_ERROR, "MFI_AUTH_COP_REG_ADDR_DEV_ID %d", res);
		return res;
	}
	*deviceid = deviceidbuf[0] << 24;
	*deviceid += deviceidbuf[1] << 16;
	*deviceid += deviceidbuf[2] << 8;
	*deviceid += deviceidbuf[3];
	return 0;
}

/**
 * processes a given challenge by forwarding to the MFI coprocessor and waiting a response
 *
 * sends the provided challenge to the authentication coprocessor, awaits and
 * fetches the response when ready.
 *
 * @param challengebuf:  buffer that contains the challenge
 * @param challengelen:  length of the challenge
 * @param responsebuf:  buffer to which challenge response is to be written
 * @param responselen:  location to which challenge response length is to be written
 *
 * @return 0 is successful, nonzero if not
 */
int mfi_auth_processchallenge(unsigned char *challengebuf, int challengelen,
		unsigned char *responsebuf, int *responselen) {
	int timeoutcount = 0;
	int done = FALSE;
	int res;
	unsigned char lenfield[2];
	unsigned char statusreg;
	int i;

	lenfield[0] = (challengelen / 256);
	lenfield[1] = (challengelen & 0xFF);
	res = mfi_auth_i2c_write_reg(MFI_AUTH_COP_REG_ADDR_CHALLENGE_LEN, lenfield,
			sizeof(lenfield));
	if (res != 0) {
		iphoned_log(IPHONEDLOG_ERROR,
				"MFI_AUTH_COP_REG_ADDR_CHALLENGE_LEN fail %d %d", challengelen,
				res);
	}

	res = mfi_auth_i2c_write_reg(MFI_AUTH_COP_REG_ADDR_CHALLENGE_DATA,
			challengebuf, challengelen);
	if (res != 0) {
		iphoned_log(IPHONEDLOG_ERROR,
				"MFI_AUTH_COP_REG_ADDR_CHALLENGE_DATA fail %d %d", challengelen,
				res);
	}

	// PROC_CONTROL = 1;
	statusreg = 1;
	res = mfi_auth_i2c_write_reg(MFI_AUTH_COP_REG_ADDR_AUTH_CTRL_AND_STATUS,
			&statusreg, sizeof(statusreg));
	if (res != 0) {
		iphoned_log(IPHONEDLOG_ERROR,
				"MFI_AUTH_COP_REG_ADDR_AUTH_CTRL_AND_STATUS 1 %d %d",
				(int) statusreg, res);
	}

	while ((timeoutcount++ < MAX_MFI_TIMEOUT) && (done == FALSE)) {
		res = mfi_auth_i2c_read_reg(MFI_AUTH_COP_REG_ADDR_AUTH_CTRL_AND_STATUS,
				&statusreg, 1);
		if (res == 0) {
			// check for challenge response availability
			if ((statusreg & 0x70) == 0x10) {
				done = TRUE;
				continue;
			}
		}
		usleep(10000);
	}
	if (timeoutcount < MAX_MFI_TIMEOUT) {
		// fetch the response length
		res = mfi_auth_i2c_read_reg(MFI_AUTH_COP_REG_ADDR_SIGNATURE_LEN,
				lenfield, sizeof(lenfield));
		if (res == 0) {
			*responselen = (lenfield[0] * 256) + lenfield[1];
		} else {
			iphoned_log(IPHONEDLOG_ERROR,
					"MFI_AUTH_COP_REG_ADDR_SIGNATURE_LEN %d %d", res,
					*responselen);
			return -1;
		}

		// fetch the response
		res = mfi_auth_i2c_read_reg(MFI_AUTH_COP_REG_ADDR_SIGNATURE_DATA,
				responsebuf, AUTHCHALLENGERESPONSE_MAX_SZ);
		if (res == 0) {
		} else {
			iphoned_log(IPHONEDLOG_ERROR,
					"MFI_AUTH_COP_REG_ADDR_SIGNATURE_DATA %d", res);
			return -1;
		}
		return 0;
	} else {
		return -1;
	}
}
