#ifndef USB_H_
#define USB_H_

#include <libusb.h>

int usb_start();
int usb_isiphonepresent();
void usb_stop(void);
void usb_forward_iphone_data(unsigned char *buf, int len);

void usb_iui_send(char * iappkt, int pktlen);
#endif /* USB_H_ */
