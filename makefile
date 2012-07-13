# Makefile for Coolfire Project
#CC=gcc
CC=arm-fsl-linux-gnueabi-gcc
CFLAGS=-DUSBMUXD_DAEMON -DUSBMUXD_VERSION="1" -I. -I../libusb-1.0.8/libusb -lusb-1.0 -I ../fs/usr/include/libusb-1.0 -L ../fs/usr/lib
##CFLAGS=-DUSBMUXD_DAEMON -DUSBMUXD_VERSION="1" -I. -I../libusb-1.0.8/libusb/ -L../fs/usr/lib/ -L/usr/lib -lusb-1.0
# All dependencies should be listed here
# to assure they get rebuilt on change
DEPS=iphoned.h iap.h log.h server.h mfi_auth.h usb.h
# All object files listed here
OBJ=iphoned.o usb.o log.o server.o mfi_auth.o iap.o

# build all objects from all c files.
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

iphoned: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f ./*.o
