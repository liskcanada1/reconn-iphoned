//******************************************************************************
//******************************************************************************
//
// FILE:        server.c
//
// DESCRIPTION: implements concurrent TCP socket server for iphoned
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
//           First fixed in 2004, all rights reserved.
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

#include <sys/socket.h>
#include <libusb.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <netdb.h>

#include "iphoned.h"
#include "log.h"
#include "server.h"
#include "usb.h"

// --------------------------------
// iphoned protocol definitions  (match this up to iphoned server.c)
#define MAXPKTLEN 1024
#define PKTHEADER_LEN 3

#define IPHONED_PORT            1069
#define START_BYTE               0x89
#define ESCAPE_BYTE              'a'

#define MSG_REPORT_IPHONE_PRESENCE 0x88
#define MSG_FORWARD_DATA 0x02
#define MSG_REPORT_DATA 0x03

#define IPHONE_NOT_PRESENT 0x00
#define IPHONE_PRESENT 0x01
//-----------------------------------------------------

static pthread_t serverthread;
static int serverthreadrunning;
static int connection_socket_fd = -1;
static int listening_socket_fd;

static struct sockaddr_in client_addr;
static int intport = 0;
static socklen_t client_len;
static unsigned char sockrxbuf[MAXPKTLEN];

static void send_sock_msg(unsigned char cmdid, unsigned char *outbuf, int len);
static void clientloop(void);
static void reportiphonepresence(int presence);
static void *serverloop(void *ptr);
static void process_msg_forward_data(unsigned char *buf, int len);
static void processmsg(unsigned char *msgbuf, int len);
static void processrx(unsigned char *inbuf, int len);

/**
 * attempts to report iphone presence to connected client
 *
 * Constructs the MSG_REPORT_IPHONE_PRESENCE and passes it to try to send
 * to client.
 *
 * @param presence:  1 if connected, 0 if not connected
 *
 */
static void reportiphonepresence(int presence) {
	unsigned char buf[1];
	buf[0] = (unsigned char) presence;
	send_sock_msg(MSG_REPORT_IPHONE_PRESENCE, buf, 2);
}

/**
 * looping function that manages and receives from a client socket until it is disconnected
 *
 * loops waiting for data from the socket until the file descriptor is cleared or there is an
 * error on the socket.
 */
static void clientloop(void) {
	int res;
	fd_set clientfdset;
	struct timeval timeout;

	// client is connected - send an initial iphone presence report to the client
	for (;;) {
		if (connection_socket_fd >= 0) {
			timeout.tv_sec = 1;
			timeout.tv_usec = 0;
			FD_ZERO(&clientfdset); /* clear the set */
			FD_SET(connection_socket_fd, &clientfdset); /* add our file descriptor to the set */
			res = select(connection_socket_fd + 1, &clientfdset, NULL, NULL,
					&timeout);
			if (res == -1) {
				// error
			} else if (res == 0) {
				// timeout
			} else {
				// the FD is pending
				if (connection_socket_fd >= 0) {
					res = recv(connection_socket_fd, sockrxbuf, 1, 0); // block on socket RX file descriptor
					if (res >= 0) {
						processrx(sockrxbuf, res);
					} else {
						// error reading from FD.  this can't be a timeout.
						return;
					}
				} else {
					// socket is disconnected or otherwise.  we're done.
					return;
				}
			}
		} else {
			// socket is disconnected or otherwise.  we're done.
			return;
		}
	}
}

/**
 * pthread loop that monitors a listening socket for connection and executes a single client loop
 *
 * takes an already-bound listening socket and pends until the listening socket is closed or error
 * occurs.  when a connection is established, immediately executes client loop.  continues to listen
 * and accept if client loop returns.  also reports current iphone presence upon connection.
 * exits if the listening file descriptor is gone.
 *
 * @param ptr:  purposeless pointer to comply with expected pthread function prototype
 *
 */
static void *serverloop(void *ptr) {
	int res;
	fd_set serverfdset;
	struct timeval timeout;

	serverthreadrunning = TRUE;
	while (1) {
		if (listening_socket_fd < 0) {
			iphoned_log(IPHONEDLOG_INFO, "server end");
			serverthreadrunning = FALSE;
			return 0;
		}
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		FD_ZERO(&serverfdset); /* clear the set */
		FD_SET(listening_socket_fd, &serverfdset); /* add our file descriptor to the set */
		res = select(listening_socket_fd + 1, &serverfdset, NULL, NULL,
				&timeout);
		if (res == -1) {
			// error
		} else if (res == 0) {
			// timeout
		} else {
			// action pending on FD
			connection_socket_fd = accept(listening_socket_fd,
					(struct sockaddr *) &client_addr, &client_len);
			if (connection_socket_fd < 0) {
				iphoned_log(IPHONEDLOG_ERROR,
						"Client Failed to open new socket. %d", errno);
			}
			if (connection_socket_fd >= 0) {
				iphoned_log(IPHONEDLOG_INFO, "client open %d",
						connection_socket_fd);
				reportiphonepresence(usb_isiphonepresent());
				clientloop();
				iphoned_log(IPHONEDLOG_INFO, "client end");
			}
		}
	}
	serverthreadrunning = FALSE;
}

/**
 * starts server by binding listening socket and starting server loop thread
 *
 * binds listening socket to localhost and starts the listening server loop
 *
 * @param ptr:  purposeless pointer to comply with expected pthread function prototype
 *
 */
int server_start(void) {
	int res;
	int on;
	struct hostent *hp;
	struct sockaddr_in server_addr;

	/* Create the incomming (server) socket */
	listening_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listening_socket_fd < 0) {
		iphoned_log(IPHONEDLOG_ERROR,
				"Server Failed to initialize the incoming socket %d", errno);
		return -1;
	}
	hp = gethostbyname("127.0.0.1");
	bcopy(hp->h_addr, &(server_addr.sin_addr.s_addr), hp->h_length);

	bzero((unsigned char *) &server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;

	server_addr.sin_addr.s_addr = INADDR_ANY;
	intport = IPHONED_PORT;
	server_addr.sin_port = htons(intport);
	on = 1;
	res = setsockopt(listening_socket_fd, SOL_SOCKET, SO_REUSEADDR, &on,
			sizeof(on));
	res = bind(listening_socket_fd, (struct sockaddr *) &server_addr,
			sizeof(server_addr));
	if (res < 0) {
		iphoned_log(IPHONEDLOG_ERROR, "Server Failed to bind the socket %d %d",
				res, errno);
		close(listening_socket_fd);
		return -1;
	}
	res = listen(listening_socket_fd, 1);
	if (res < 0) {
		iphoned_log(IPHONEDLOG_ERROR, "Bound socket error %d", res);
	}
	client_len = sizeof(client_addr);

	res = pthread_create(&serverthread, NULL, serverloop, (void*) "listenloop");
	if (res != 0) {
		iphoned_log(IPHONEDLOG_ERROR, "failed to create listenloop");
		close(listening_socket_fd);
		return -1;
	}
	return 0;
}

/**
 * builds packet from constructed messages and attempts to send to client
 *
 * if client is connected, uses parameters to construct packet by adding start byte, length bytes and escape
 * characters where necessary.
 *
 * @param cmdid:  command ID of packet to send
 * @param outbuf:  buffer containing message to send
 * @param len:  length of buffer containing message
 *
 */
static void send_sock_msg(unsigned char cmdid, unsigned char *outbuf, int len) {
	unsigned char *buf;
	int i = 0;
	int bufidx = 0;
	unsigned char tmp;
	int res;
	int msglen = len + 1;

	if (connection_socket_fd != -1) {
		buf = malloc(len * 2 + 3);
		buf[bufidx++] = START_BYTE;
		tmp = msglen / 256;
		if ((tmp == ESCAPE_BYTE) || (tmp == START_BYTE)) {
			buf[bufidx++] = ESCAPE_BYTE;
		}
		buf[bufidx++] = tmp;
		tmp = msglen & 0xFF;
		if ((tmp == ESCAPE_BYTE) || (tmp == START_BYTE)) {
			buf[bufidx++] = ESCAPE_BYTE;
		}
		buf[bufidx++] = tmp;
		if ((cmdid == ESCAPE_BYTE) || (cmdid == START_BYTE)) {
			buf[bufidx++] = ESCAPE_BYTE;
		}
		buf[bufidx++] = cmdid;
		for (i = 0; i < len; ++i) {
			tmp = outbuf[i];
			if ((tmp == ESCAPE_BYTE) || (tmp == START_BYTE)) {
				buf[bufidx++] = ESCAPE_BYTE;
			}
			buf[bufidx++] = outbuf[i];
		}
		res = send(connection_socket_fd, buf, bufidx, 0);
		free(buf);
	}
}

/**
 * processes MSG_FORWARD_DATA buffer and passes data to USB module for sending to iPhone
 *
 * passes provided buffer and length to USB module for sending to iPhone
 *
 * @param buf:  pointer to data buffer (without command ID)
 * @param len:  length of buffer containing data
 *
 */
static void process_msg_forward_data(unsigned char *buf, int len) {
	usb_forward_iphone_data(buf, len);
}

/**
 * Message parser for iphoned protocol messages.
 *
 * manages processing of all messages received from iphoned
 * by calling a handler function and passing the message data.
 *
 * @param msgbuf:  pointer to buffer that holds message to be processed
 * @param len:  length of data to be sent
 */
static void processmsg(unsigned char *msgbuf, int len) {
	switch (msgbuf[0]) {
	case MSG_FORWARD_DATA:
		process_msg_forward_data(&(msgbuf[1]), len - 1);
		break;
	default:
		break;
	}
}

/**
 * Stateful packet parser for iphoned packets
 *
 * manages processing of all data received from iphoned.
 * Escape sequences are decoded and resulting data is parsed into packets.
 * The packets are provided to a parsing function.  State is retained between
 * calls.
 *
 * @param inbuf:  buffer that holds message to be processed
 * @param len:  length of data to be sent
 */
static void processrx(unsigned char *inbuf, int len) {
	// persistent
	static int packetpos = 0;
	static unsigned char currpkt[MAXPKTLEN];
	static int is_escaped = FALSE;
	static int msglen = 0;

	int inbufpos = 0;
	unsigned char currbyte;
	unsigned int ctrlbyte = FALSE;

	while (inbufpos < len) {
		// handle escape and control data detection
		ctrlbyte = -1;
		if (is_escaped == TRUE) {
			currbyte = inbuf[inbufpos];
			is_escaped = FALSE;
		} else if ((is_escaped == FALSE) && (inbuf[inbufpos] == ESCAPE_BYTE)) {
			is_escaped = TRUE;
		} else if ((is_escaped == FALSE) && (inbuf[inbufpos] == START_BYTE)) {
			currbyte = START_BYTE;
			ctrlbyte = TRUE;
		} else {
			currbyte = inbuf[inbufpos];
			is_escaped = FALSE;
		}
		inbufpos++;

		// process decoded packet data
		if (is_escaped != TRUE) {
			if ((packetpos == 0) && (ctrlbyte != TRUE)) {
				// out of packet data - do nothing
			} else if (ctrlbyte == TRUE) {
				ctrlbyte = FALSE;
				if (currbyte == START_BYTE) {
					packetpos = 0;
					ctrlbyte = 0;
					++packetpos;
					msglen = 0;
				}
			} else if (packetpos == 1) {
				msglen += currbyte * 256;
				++packetpos;
			} else if (packetpos == 2) {
				msglen += currbyte;
				++packetpos;
			} else if (packetpos <= (msglen + 3)) {
				currpkt[packetpos - 3] = currbyte;
				++packetpos;
			}

			// check for packet complete and process if complete
			if ((packetpos > 2) && (packetpos >= (msglen + 3))) {
				processmsg(currpkt, msglen);
				packetpos = 0;
			}
		}
	}
}

/**
 * attempts to report iphone presence status to client
 *
 * calls iphone presence report function with provided status
 *
 * @param status:  TRUE if iPhone present and data session established.  any other value otherwise.
 */
void server_report_iphone_connect(int status) {
	if (status == TRUE) {
		reportiphonepresence(1);
	} else {
		reportiphonepresence(0);
	}
}

/**
 * stops any running server thread and client loops
 *
 * closes active file descriptors for server and client and waits for server
 * thread to terminate
 *
 */
void server_stop(void) {
	int res;

	iphoned_log(IPHONEDLOG_INFO, "server_stop %d %d", connection_socket_fd,
			listening_socket_fd);
	if (connection_socket_fd >= 0) {
		res = close(connection_socket_fd);
		iphoned_log(IPHONEDLOG_INFO, "connection_socket_fd close %d", res);
		connection_socket_fd = -1;
	}
	if (listening_socket_fd >= 0) {
		res = close(listening_socket_fd);
		listening_socket_fd = -1;
	}

	while (serverthreadrunning == TRUE) {
	}
}

/**
 * attempts to forward data from iPhone application to client
 *
 * attempts to send the provided data as is to the client
 *
 * @param buf:  pointer to data to be sent
 * @param len:  length of data to be sent
 */
void server_forwardapplicationdata(unsigned char *buf, int len) {
	send_sock_msg(MSG_REPORT_DATA, buf, len);
}
