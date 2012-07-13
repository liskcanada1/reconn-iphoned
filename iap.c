//******************************************************************************
//******************************************************************************
//
// FILE:        iap.c
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
#include <malloc.h>
#include <string.h>
#include <time.h>

#include "iphoned.h"
#include "iap.h"
#include "log.h"
#include "usb.h"
#include "mfi_auth.h"

#define AUTHCHALLENGE_MAX_SZ 40

// IAP Lingo List
#define IAP_LINGO_GENERAL 0

// IAP Header Information
#define IAP_START_BYTE 0x55

// Lingo 0 - General IAP Message IDs
#define IAP_MSG_REQUESTIDENTIFY 0x00
#define IAP_MSG_ACK 0x02
#define IAP_MSG_REQUESTTRANSPORTMAXPAYLOADSIZE 0x11
#define IAP_MSG_RETURNTRANSPORTMAXPAYLOADSIZE 0x12
#define IAP_MSG_GETDEVAUTHENTICATIONINFO 0x14
#define IAP_MSG_RETDEVAUTHENTICATIONINFO 0x15
#define IAP_MSG_ACKDEVAUTHENTICATIONINFO 0x16
#define IAP_MSG_GETACCESSORYAUTHENTICATIONSIGNATURE 0x17
#define IAP_MSG_RETACCESSORYAUTHENTICATIONSIGNATURE 0x18
#define IAP_MSG_ACKACCESSORYAUTHENTICATIONSTATUS 0x19
#define IAP_MSG_STARTIDPS 0x38
#define IAP_MSG_SETFIDTOKENVALUES 0x39
#define IAP_MSG_RETFIDTOKENVALUEACKS 0x3A
#define IAP_MSG_ENDIDPS 0x3B
#define IAP_MSG_IDPSSTATUS 0x3C
#define IAP_MSG_OPENDATASESSIONFORPROTOCOL 0x3F
#define IAP_MSG_CLOSEDATASESSION 0x40
#define IAP_MSG_ACCESSORYACK 0x41
#define IAP_MSG_DEVDATATRANSFER 0x42
#define IAP_MSG_IPODDATATRANSFER 0x43
#define IAP_MSG_REQUESTAPPLICATIONLAUNCH 0x64

// structures to form token data for IAP recipient
typedef struct {
	unsigned char length;
	unsigned char type;
	unsigned char subtype;

// must be at end of struct
// placeholder is to make this struct fit evenly in 'int' size blocks.  this isn't the greatest approach
// and it is preferable to find a more portable method of ensuring the correct data alignment/size.
	unsigned char placeholder;
	unsigned char *data;
	int datasz;
} fidtoken_t;

typedef struct {
	unsigned char type;

// must be at end of struct
// placeholder is to make this struct fit evenly in 'int' size blocks.  this isn't the greatest approach
// and it is preferable to find a more portable method of ensuring the correct data alignment/size.
	unsigned char placeholder[3];
	unsigned char *data;
	int datasz;
} accinfo_t;

typedef struct {
	unsigned char cmdid; // command ID which shall be included in ACK message
	int transactionid; // transaction ID which shall be included in ACK message
	unsigned char expectedresult; // result code which shall be included in ACK message
	time_t starttime; // starting time for ACK timeout
	int timeoutsec; // number of seconds to wait for ACK timeout
	int received; // FALSE if matching ACK hasn't been received, TRUE if it has
} ackwait_t;

enum {
	ACKSTATUS_WAITING = 0, ACKSTATUS_TIMEOUT, ACKSTATUS_RECEIVED
};

typedef enum {
	IPHONESTATE_JUSTCONNECTED = 0,
	IPHONESTATE_STARTIDPS_SENT,
	IPHONESTATE_REQUESTMAXPAYLOADSIZE_SENT,
	IPHONESTATE_SETFIDTOKENVALUES_SENT,
	IPHONESTATE_ENDIDPS_SENT,
	IPHONESTATE_RETDEVAUTHENTICATIONINFO_SENT,
	IPHONESTATE_RETDEVAUTHENTICATIONSIGNATURE_SENT,
	IPHONESTATE_AUTHENTICATED_NOSESSION,
	IPHONESTATE_AUTHENTICATED_SESSIONOPEN_READY,
	IPHONESTATE_AUTHENTICATED_SESSIONOPEN_WAIT
} iapstate_t;

// ackwait structure holds ack timeout information
// ackwait structure is processed by
//	* IAP state machine:
//		* set ACK timer
//		* cancel ACK timer
//		* detect ACK timeout
//	* IAP message RX routine
//		* detect ACK and satisified ACK condition
static ackwait_t ackwait;

static int iap_maxpayloadsize;
static iapstate_t iapstate;
static int usbiap_incomingtransactionid;
static int usbiap_outgoingtransactionid = 0;
static unsigned char authchallenge[AUTHCHALLENGE_MAX_SZ];
static int authchallengelen;
static int iap_authchallengereceived;
static int iap_authentcationstatusok;
static int iap_sessionopen;
static int iap_opensessionid;
static int iap_maxpayloadsize;
static int iap_requestmaxpayloadsizereceived;
static int iap_retfidtokenvalueacksreceived;
static int iap_getdevauthenticationinforeceived;
static int iap_certificateaccepted;
static int iap_idpsstatusreceived;
static int iap_deviceid;
static unsigned char iap_auth_cert[AUTH_CERT_MAX_SZ];
static int iap_auth_cert_len;

static int iap_wait_for_ack(int cmdid);
static void iap_process_packet(int lingoid, int cmdid, unsigned char *databuf,
		int datalen);
static void iap_sendStartIdps(void);
static void iap_sendEndIDPS(void);
static void iap_sendSetFIDTokenValues(void);
static void iap_sendGetDevAuthenticationInfo(void);
static void iap_processack(unsigned char *databuf, int datalen);
static void iap_sendDevDataTransfer(int sessionid, char *buf, int len);
static void iap_processiPodDataTransfer(unsigned char *buf, int len);
static void iap_processAckDevAuthentcationInfo(unsigned char *buf, int len);
static void iap_processRequestIdentify(unsigned char *buf, int len);
static void iap_sendRetDevAuthenticationInfo(unsigned char *certbuf,
		int certlen);
static void iap_setRetAccessoryAuthenticationSignature(unsigned char *sigbuf,
		int siglen);
static void iap_processGetAccessoryAuthenticationSignature(unsigned char *buf,
		int len);
static void iap_processAckAccessoryAuthenticationStatus(unsigned char *buf,
		int len);
static void iap_processOpenDataSessionForProtocol(unsigned char *buf, int len);
static void iap_processCloseDataSession(unsigned char *buf, int len);
static void iap_sendAccessoryAck(unsigned char cmdid, unsigned char status);
static int iap_getnextoutgoingtransactionid(void);
static void iap_sendRequestTransportMaxPayloadSize(void);
static void usb_iap_processReturnTransportMaxPayloadSize(unsigned char *databuf,
		int datalen);
static void iap_sendRequestApplicationLaunch(unsigned char *appbundleid,
		int len);
static int iap_buildaccinfoatbuf(unsigned char *buf, accinfo_t *accinfo);
static void iap_build_packet_and_send(unsigned char * payloaddatabuf,
		int payloaddatalen, int lingoid, int commandid, int transactionid,
		int withtransactionid, int setupackwait);
static unsigned char iap_checksum(unsigned char *buf, int len);
static int iap_ack_status(void);
static void iap_forceackreceived(void);
static void iap_initwaitwack(unsigned char cmdid, int transactionid,
		int expectedresult, int timeoutsec);

/**
 * initializes ackwait structure for an ack timeout starting at calling time
 *
 * fills the ackwait structure as provided to set up a new ACK timeout
 *
 * @param cmdid:  command ID which must be included with ACK
 * @param transactionid:  transaction ID which must be included with ACK
 * @param expectedresult:  result code which must be included with ACK
 * @param timeoutsec:  seconds to wait before timeout
 */
static void iap_initwaitwack(unsigned char cmdid, int transactionid,
		int expectedresult, int timeoutsec) {
	ackwait.cmdid = cmdid;
	ackwait.transactionid = transactionid;
	ackwait.expectedresult = expectedresult;
	time(&ackwait.starttime);
	ackwait.timeoutsec = timeoutsec;
	ackwait.received = FALSE;
}

/**
 * calculates simple 8-bit checksum for given IAP buffer
 *
 * returns a checksum by adding each byte of a buffer to an 8-bit
 * accumulator, truncating overflow
 *
 * @param buf:  buffer for which to calculate checksum
 * @param len:  length of buffer
 *
 * @return checksum calculated
 */
static unsigned char iap_checksum(unsigned char *buf, int len) {
	int i;
	unsigned char checksum = 0;

	for (i = 0; i < len; ++i) {
		checksum += buf[i];
	}
	checksum = ~checksum;
	return ++checksum;
}

/**
 * builds IAP packet for given payload and attempts to send to IAP device
 *
 * - builds IAP packet with given information
 * - sets up ACK waiting if specified
 * - forwards to iUI function for a send attempt
 *
 * @param payloaddatabuf:  buffer that contains payload to send
 * @param payloaddatalen:  length of payload
 * @param lingoid:  iAP lingo ID of packet to send
 * @param commandid:  iAP command ID of packet to send
 * @param transactionid:  iAP transaction ID of packet to send
 * @param withtransactionid:  TRUE if transaction ID is to be included.  not TRUE otherwise.
 * @param setupackwait:  TRUE if ACK wait is to be set up.  not TRUE otherwise.
 *
 */
static void iap_build_packet_and_send(unsigned char * payloaddatabuf,
		int payloaddatalen, int lingoid, int commandid, int transactionid,
		int withtransactionid, int setupackwait) {
	unsigned char *iapbuf;
	int iappos = 0;
	int i;
	unsigned char chksum = 0;
	int payloadlen;

	if (setupackwait == TRUE) {
		// always need '0' expected result
		iap_initwaitwack(commandid, transactionid, 0, 5);
	}

	// the actual iAP payload contains the lingo ID and command ID also but we keep the common aspects
	// of a packet hidden
	payloadlen = payloaddatalen + 2;
	if (withtransactionid == TRUE) {
		// transaction ID is actually in the payload proper
		payloadlen = payloadlen + 2;
	}

	if (payloadlen <= 255) {
		// construct the 'short' form packet with one length byte
		iapbuf = malloc(3 + payloadlen);
		iapbuf[iappos++] = IAP_START_BYTE;
		iapbuf[iappos++] = (unsigned char) payloadlen;
		iapbuf[iappos++] = lingoid;
		iapbuf[iappos++] = commandid;
		if (withtransactionid == TRUE) {
			iapbuf[iappos++] = (transactionid / 256);
			iapbuf[iappos++] = (transactionid & 0xFF);
		}
		if (payloaddatalen != 0) {
			memcpy(&(iapbuf[iappos]), payloaddatabuf, payloaddatalen);
			iappos += payloaddatalen;
		}
		iapbuf[iappos++] = iap_checksum(&(iapbuf[1]), iappos - 1);
	} else if (payloadlen < iap_maxpayloadsize) {
		// construct the 'long' form packet with two length bytes
		iapbuf = malloc(5 + payloadlen);
		iapbuf[iappos++] = 0x55;
		iapbuf[iappos++] = 0x00; // payload length marker
		iapbuf[iappos++] = (unsigned char) (payloadlen / 256);
		iapbuf[iappos++] = (unsigned char) (payloadlen & 0xFF);
		iapbuf[iappos++] = lingoid;
		iapbuf[iappos++] = commandid;
		if (withtransactionid == TRUE) {
			iapbuf[iappos++] = (transactionid / 256);
			iapbuf[iappos++] = (transactionid & 0xFF);
		}
		if (payloaddatalen != 0) {
			memcpy(&(iapbuf[iappos]), payloaddatabuf, payloaddatalen);
			iappos += payloaddatalen;
		}
		iapbuf[iappos++] = iap_checksum(&(iapbuf[1]), iappos - 1);
	}

	// attempt to send the packet via iUI
	iphoned_log(IPHONEDLOG_SPEW, "iap sent packet cmd %x packetsz %d",
			commandid, iappos);
	usb_iui_send(iapbuf, iappos);
	free(iapbuf);
}

/**
 * calculates simple 8-bit checksum for given IAP buffer
 *
 * returns a checksum by adding each byte of a buffer to an 8-bit
 * accumulator, truncating overflow
 *
 * @param buf:  buffer for which to calculate checksum
 * @param len:  length of buffer
 *
 * @return checksum calculated
 */
void iap_free_packet(unsigned char *buf) {
	if (buf != NULL) {
		free(buf);
	}
}

/**
 * primary state machine processor for IAP.  to be called regularly by monitoring task
 *
 * performes IAP processing including:
 * 		- sequencing and processing IAP states
 * 		- monitoring for IAP response signals
 * 		- monitoring and handle timeout conditions
 *
 * @return TRUE if a state change has occurred.  (indicates there is work yet to do)
 */
int iap_process_state(void) {
	int res;
	static iapstate_t lastiapstate = -1;
	int ackstatus = iap_ack_status();
	if (ackstatus == ACKSTATUS_TIMEOUT) {
		time_t now;
		time(&now);

		iphoned_log(IPHONEDLOG_INFO, "iAP timeout %x %f %f",
				(int) ackwait.cmdid, (double) now, (double) ackwait.starttime);
		iap_reset_connection();
	}

	switch (iapstate) {
	case IPHONESTATE_JUSTCONNECTED:
		usbiap_outgoingtransactionid = 0;
		iap_maxpayloadsize = 65535; // initialize so we can send packets
		iap_sendStartIdps();
		iapstate = IPHONESTATE_STARTIDPS_SENT;
		iap_sessionopen = FALSE;
		break;
	case IPHONESTATE_STARTIDPS_SENT:
		if (ackstatus == ACKSTATUS_RECEIVED) {
			iap_requestmaxpayloadsizereceived = FALSE;
			iap_sendRequestTransportMaxPayloadSize();
			iapstate = IPHONESTATE_REQUESTMAXPAYLOADSIZE_SENT;
		}
		break;
	case IPHONESTATE_REQUESTMAXPAYLOADSIZE_SENT:
		if (iap_requestmaxpayloadsizereceived == TRUE) {
			iap_retfidtokenvalueacksreceived = FALSE;
			iap_sendSetFIDTokenValues();
			iapstate = IPHONESTATE_SETFIDTOKENVALUES_SENT;
		}
		break;
	case IPHONESTATE_SETFIDTOKENVALUES_SENT:
		if (iap_retfidtokenvalueacksreceived == TRUE) {
			iap_sendEndIDPS();
			iap_idpsstatusreceived = FALSE;
			iap_getdevauthenticationinforeceived = FALSE;
			iapstate = IPHONESTATE_ENDIDPS_SENT;
		}
		break;
	case IPHONESTATE_ENDIDPS_SENT:
		if ((iap_idpsstatusreceived == TRUE)
				&& (iap_getdevauthenticationinforeceived == TRUE)) {
			iap_certificateaccepted = FALSE;
			iap_authchallengereceived = FALSE;
			iap_sendRetDevAuthenticationInfo(iap_auth_cert, iap_auth_cert_len);
			iapstate = IPHONESTATE_RETDEVAUTHENTICATIONINFO_SENT;
		}
		break;
	case IPHONESTATE_RETDEVAUTHENTICATIONINFO_SENT:
		if (iap_certificateaccepted == TRUE) {
			static unsigned char authchallengeresponse[AUTHCHALLENGERESPONSE_MAX_SZ];
			static int authchallengeresponselen;

			if (iap_authchallengereceived == TRUE) {
				res = mfi_auth_processchallenge(authchallenge, authchallengelen,
						authchallengeresponse, &authchallengeresponselen);
				if (res == 0) {
					iap_authentcationstatusok = FALSE;
					iap_setRetAccessoryAuthenticationSignature(
							authchallengeresponse, authchallengeresponselen);
					iapstate = IPHONESTATE_RETDEVAUTHENTICATIONSIGNATURE_SENT;
				} else {
					iphoned_log(IPHONEDLOG_ERROR,
							"mfi_auth_processchallenge fail %d", res);
				}
			}
		}
		break;
	case IPHONESTATE_RETDEVAUTHENTICATIONSIGNATURE_SENT:
		if (iap_authentcationstatusok == TRUE) {
			iap_sendRequestApplicationLaunch(MFI_APP_STARTUP_BUNDLE_NAME,
					strlen(MFI_APP_STARTUP_BUNDLE_NAME) + 1);
			iap_forceackreceived();
			iapstate = IPHONESTATE_AUTHENTICATED_NOSESSION;
			// we ignore result for this application launch in case the application isn't
			// installed.
		}
		break;
	case IPHONESTATE_AUTHENTICATED_NOSESSION:
		if (iap_sessionopen == TRUE) {
			iapstate = IPHONESTATE_AUTHENTICATED_SESSIONOPEN_READY;
		}
		break;
	case IPHONESTATE_AUTHENTICATED_SESSIONOPEN_READY:
		if (iap_sessionopen != TRUE) {
			iapstate = IPHONESTATE_AUTHENTICATED_NOSESSION;
		}
		break;
	case IPHONESTATE_AUTHENTICATED_SESSIONOPEN_WAIT:
		if (ackstatus == ACKSTATUS_RECEIVED) {
			iapstate = IPHONESTATE_AUTHENTICATED_SESSIONOPEN_READY;
		}
		break;
	}

	if (iapstate != lastiapstate) {
		iphoned_log(IPHONEDLOG_INFO, "iAP state %d", iapstate);
		lastiapstate = iapstate;
		return TRUE;
	}
	return FALSE;
}

/**
 * resets IAP connection and states
 *
 * triggers a reset of IAP connection and connection states
 *
 */
void iap_reset_connection(void) {
	iapstate = IPHONESTATE_JUSTCONNECTED;
}

/**
 * parser for stateful stream of iAP protocol data
 *
 * parses stream of iAP data, decodes and reports packets.  maintains
 * state between calls.
 *
 * @param buf:  buffer of data to process
 * @param len:  length of buffer
 *
 */
void iap_parsestream(unsigned char *buf, int len) {
	int bufpos;
	static int iappos = 0;
	static int packettype; // 1 if large packet type, 2 if small packet type
	static int iappayloadlen;
	static int iaplingoid;
	static int iapcommandid;
	static unsigned char databuf[65535];
	static int payloadpos = 0; // -1 if processing header

	for (bufpos = 0; bufpos < len; ++bufpos) {
		if (iappos == 0) {
			// check for start byte
			if (buf[bufpos] == 0x55) {
				++iappos;
				payloadpos = -1;
				continue;
			}
		} else {
			if (payloadpos == -1) {
				if (iappos == 1) {
					if (buf[bufpos] == 0) {
						packettype = 1;
					} else {
						packettype = 0;
						iappayloadlen = buf[bufpos];
						payloadpos = 0;
					}
				}
				if (iappos == 2) {
					if (packettype == 1) {
						iappayloadlen = buf[bufpos] * 256;
					} else {
						iaplingoid = buf[bufpos];
					}
				}
				if (iappos == 3) {
					if (packettype == 1) {
						iappayloadlen += buf[bufpos];
						payloadpos = 0;
					} else {
						iapcommandid = buf[bufpos];
					}
				}
				++iappos;
			} else {
				if (payloadpos == 0) {
					iaplingoid = buf[bufpos];
				} else if (payloadpos == 1) {
					iapcommandid = buf[bufpos];
				} else if (payloadpos < iappayloadlen) {
					databuf[payloadpos - 2] = buf[bufpos];
				} else {
					// checksum byte.  toss it out and process the packet
					iap_process_packet(iaplingoid, iapcommandid, databuf,
							payloadpos - 2);
					iappos = 0;
				}
				++payloadpos;
			}
		}
	}
}

/**
 * handles parsed iAP packet
 *
 * determines packet command ID and performs individual handling when a flag change is
 * required or calls handlers.  if packet is not recognized, does nothing.
 *
 * @param lingoid:  lingo ID of packet to handle
 * @param cmdid:  command ID of packet to handle
 * @param databuf:  buffer containing packet data
 * @param datalen:  buffer containing packet data length in buffer
 *
 */
static void iap_process_packet(int lingoid, int cmdid, unsigned char *databuf,
		int datalen) {
	switch (lingoid) {
	case IAP_LINGO_GENERAL:
		switch (cmdid) {
		case IAP_MSG_REQUESTIDENTIFY:
			iap_processRequestIdentify(databuf, datalen);
			break;
		case IAP_MSG_ACK:
			iap_processack(databuf, datalen);
			break;
		case IAP_MSG_GETDEVAUTHENTICATIONINFO:
			usbiap_incomingtransactionid = (databuf[0] * 256 + databuf[1]);
			iap_getdevauthenticationinforeceived = TRUE;
			break;
		case IAP_MSG_RETFIDTOKENVALUEACKS:
			iap_retfidtokenvalueacksreceived = TRUE;
			break;
		case IAP_MSG_IDPSSTATUS:
			iap_idpsstatusreceived = TRUE;
			break;
		case IAP_MSG_IPODDATATRANSFER:
			usbiap_incomingtransactionid = (databuf[0] * 256 + databuf[1]);
			iap_processiPodDataTransfer(databuf, datalen);
			break;
		case IAP_MSG_RETURNTRANSPORTMAXPAYLOADSIZE:
			usb_iap_processReturnTransportMaxPayloadSize(databuf, datalen);
			break;
		case IAP_MSG_ACKDEVAUTHENTICATIONINFO:
			iap_processAckDevAuthentcationInfo(databuf, datalen);
			break;
		case IAP_MSG_GETACCESSORYAUTHENTICATIONSIGNATURE:
			usbiap_incomingtransactionid = (databuf[0] * 256 + databuf[1]);
			iap_processGetAccessoryAuthenticationSignature(databuf, datalen);
			break;
		case IAP_MSG_ACKACCESSORYAUTHENTICATIONSTATUS:
			iap_processAckAccessoryAuthenticationStatus(databuf, datalen);
			break;
		case IAP_MSG_OPENDATASESSIONFORPROTOCOL:
			usbiap_incomingtransactionid = (databuf[0] * 256 + databuf[1]);
			iap_processOpenDataSessionForProtocol(databuf, datalen);
			break;
		case IAP_MSG_CLOSEDATASESSION:
			usbiap_incomingtransactionid = (databuf[0] * 256 + databuf[1]);
			iap_processCloseDataSession(databuf, datalen);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
}

/**
 * returns next outgoing transaction ID
 *
 * determines packet command ID and performs individual handling when a flag change is
 * required or calls handlers.  if packet is not recognized, do nothing.
 *
 * @return TRUE if a state change has occurred.  (indicates there is work yet to do)
 */
static int iap_getnextoutgoingtransactionid(void) {
	int retval = usbiap_outgoingtransactionid;

	if ((++usbiap_outgoingtransactionid) > 65535) {
		usbiap_outgoingtransactionid = 0;
	}
	return retval;
}

/**
 * for a given FID token, build the FID token to be sent via IAP
 *
 * uses the fid token structure to build the FID token data to be sent via IAP.  returns
 * number of bytes in built FID token
 *
 * @param buf:  location to which to write the built FID token
 * @param token:  token as defined by fidtoken_t structure
 *
 * @return number of bytes in built FID token
 *
 */
int iap_buildfidtokenatbuf(unsigned char *buf, fidtoken_t *token) {
	int pos = 0;
	int fidtoken_sz = sizeof(*token) - sizeof(token->data)
			- sizeof(token->datasz) - sizeof(token->placeholder);

	token->length = fidtoken_sz + token->datasz - sizeof(token->length);
	memcpy(&(buf[pos]), token, fidtoken_sz);
	pos += fidtoken_sz;
	memcpy(&(buf[pos]), token->data, token->datasz);
	pos += token->datasz;
	return pos;
}

/**
 * for a accinfo structure, constructs accinfo data
 *
 * uses the accinfo structure to build the accinfo data to be sent within FIDtoken data via IAP.
 * returns number of bytes in built accinfo data
 *
 * @param buf:  location to which to write the built FID token
 * @param accinfo:  accinfo as defined by fidtaccinfooken_t structure
 *
 * @return number of bytes in built accinfo data
 *
 */
static int iap_buildaccinfoatbuf(unsigned char *buf, accinfo_t *accinfo) {
	int pos = 0;
	int accinfo_sz = sizeof(*accinfo) - sizeof(accinfo->data)
			- sizeof(accinfo->datasz) - sizeof(accinfo->placeholder);

	memcpy(&(buf[pos]), accinfo, accinfo_sz);
	pos += accinfo_sz;
	memcpy(&(buf[pos]), accinfo->data, accinfo->datasz);
	pos += accinfo->datasz;
	return pos;
}

/**
 * contructs and sends SetFIDTokenValues packet specified for this device
 *
 * constructs SetFIDtokenValues packet into a buffer, packetizes and sends
 * via IAP
 */
static void iap_sendSetFIDTokenValues(void) {
	int payloadlen;
	unsigned char payload[1000];
	int payloadpos = 0; // track progress into payload for all tokens
	unsigned int cnt = 0; // track each token
	unsigned char *packetptr;
	unsigned int packetlen;

	payload[payloadpos++] = 11; // this is the number of tokens constructed below

// Identify Token
	{
		fidtoken_t identify;
		unsigned char identifydata[10];

		cnt = 0;
		identify.type = 0;
		identify.subtype = 0;

		// load lingo configuration - only one lingo:  general lingo (0x00)
		identifydata[cnt++] = 1; // numlingoes = 1
		identifydata[cnt++] = 0; // general lingo

		// Deeviceoptions = 0x00000002
		// authenticate immediately after identification
		// power is set to 'low power mode'
		identifydata[cnt++] = 0;
		identifydata[cnt++] = 0;
		identifydata[cnt++] = 0;
		identifydata[cnt++] = 2;

		identifydata[cnt++] = iap_deviceid >> 24;
		identifydata[cnt++] = iap_deviceid >> 16;
		identifydata[cnt++] = iap_deviceid >> 8;
		identifydata[cnt++] = iap_deviceid & 0xFF;

		identify.data = identifydata;
		identify.datasz = sizeof(identifydata);
		payloadpos += iap_buildfidtokenatbuf(&(payload[payloadpos]), &identify);
	}

// AccCaps Token
	{
		fidtoken_t acccaps;
		unsigned char acccapsdata[8];

		acccaps.type = 0;
		acccaps.subtype = 1;
		cnt = 0;

		// capabilities = 0x0000000000000200  (only communication with application)
		acccapsdata[cnt++] = 0x00;
		acccapsdata[cnt++] = 0x00;
		acccapsdata[cnt++] = 0x00;
		acccapsdata[cnt++] = 0x00;
		acccapsdata[cnt++] = 0x00;
		acccapsdata[cnt++] = 0x00;
		acccapsdata[cnt++] = 0x02;
		acccapsdata[cnt++] = 0x00;
		acccaps.data = acccapsdata;
		acccaps.datasz = sizeof(acccapsdata);
		payloadpos += iap_buildfidtokenatbuf(&(payload[payloadpos]), &acccaps);
	}

// AccInfo Tokens
	{
		fidtoken_t accinfo;
		unsigned char accinfodata[1000];
		accinfo_t accessoryname;
		accinfo_t firmwareversion;
		unsigned char firmwareversiondata[3];
		accinfo_t hardwareversion;
		unsigned char hardwareversiondata[3];
		accinfo_t manufacturer;
		accinfo_t modelnum;
		accinfo_t rfcapabilities;
		unsigned char rfcapabilitiesdata[4];
		accinfo_t maxpacketsize;
		unsigned char maxpacketsizedata[2];

		accinfo.type = 0;
		accinfo.subtype = 2;

// Accinfo (accessory name)
		cnt = 0;
		accessoryname.type = 1;
		accessoryname.data = MFI_ACCESSORY_NAME;
		accessoryname.datasz = 1 + strlen(accessoryname.data);
		cnt += iap_buildaccinfoatbuf(&(accinfodata[cnt]), &accessoryname);
		accinfo.data = accinfodata;
		accinfo.datasz = cnt;
		payloadpos += iap_buildfidtokenatbuf(&(payload[payloadpos]), &accinfo);

// Accinfo (firmware version)
		cnt = 0;
		firmwareversion.type = 4;
		firmwareversiondata[0] = MFI_FIRMWARE_VERSION / 65536;
		firmwareversiondata[1] = MFI_FIRMWARE_VERSION / 256;
		firmwareversiondata[2] = MFI_FIRMWARE_VERSION & 0xFF;
		firmwareversion.data = firmwareversiondata;
		firmwareversion.datasz = sizeof(firmwareversiondata);
		cnt += iap_buildaccinfoatbuf(&(accinfodata[cnt]), &firmwareversion);
		accinfo.data = accinfodata;
		accinfo.datasz = cnt;
		payloadpos += iap_buildfidtokenatbuf(&(payload[payloadpos]), &accinfo);

// Accinfo (hardware version)
		cnt = 0;
		hardwareversion.type = 5;
		hardwareversiondata[0] = MFI_HARDWARE_VERSION / 65536;
		hardwareversiondata[1] = MFI_HARDWARE_VERSION / 256;
		hardwareversiondata[2] = MFI_HARDWARE_VERSION & 0xFF;
		hardwareversion.data = hardwareversiondata;
		hardwareversion.datasz = sizeof(hardwareversiondata);
		cnt += iap_buildaccinfoatbuf(&(accinfodata[cnt]), &hardwareversion);
		accinfo.data = accinfodata;
		accinfo.datasz = cnt;
		payloadpos += iap_buildfidtokenatbuf(&(payload[payloadpos]), &accinfo);

// Accinfo (manufacturer name)
		cnt = 0;
		manufacturer.type = 6;
		manufacturer.data = MFI_MANUFACTURER_NAME;
		manufacturer.datasz = 1 + strlen(manufacturer.data);
		cnt += iap_buildaccinfoatbuf(&(accinfodata[cnt]), &manufacturer);
		accinfo.data = accinfodata;
		accinfo.datasz = cnt;
		payloadpos += iap_buildfidtokenatbuf(&(payload[payloadpos]), &accinfo);

// Accinfo (model number)
		cnt = 0;
		modelnum.type = 7;
		modelnum.data = MFI_MODEL_NUMBER;
		modelnum.datasz = 1 + strlen(modelnum.data);
		cnt += iap_buildaccinfoatbuf(&(accinfodata[cnt]), &modelnum);
		accinfo.data = accinfodata;
		accinfo.datasz = cnt;
		payloadpos += iap_buildfidtokenatbuf(&(payload[payloadpos]), &accinfo);

// Accinfo (maximum packet size)
		cnt = 0;
		maxpacketsize.type = 9;

		// max pkt size = 65529
		maxpacketsizedata[0] = 0xFF;
		maxpacketsizedata[1] = 0xFA;
		maxpacketsize.data = maxpacketsizedata;
		maxpacketsize.datasz = 2;
		cnt += iap_buildaccinfoatbuf(&(accinfodata[cnt]), &maxpacketsize);
		accinfo.data = accinfodata;
		accinfo.datasz = cnt;
		payloadpos += iap_buildfidtokenatbuf(&(payload[payloadpos]), &accinfo);

// Accinfo (RF capabilities)
		cnt = 0;
		rfcapabilities.type = 0x0C;

		// iphone, iphone 3g, 3gs, 4g CDMA/GSM
		rfcapabilitiesdata[0] = 0x00;
		rfcapabilitiesdata[1] = 0x00;
		rfcapabilitiesdata[2] = 0x00;
		rfcapabilitiesdata[3] = 0x0B;
		rfcapabilities.data = rfcapabilitiesdata;
		rfcapabilities.datasz = 4;
		cnt += iap_buildaccinfoatbuf(&(accinfodata[cnt]), &rfcapabilities);
		accinfo.data = accinfodata;
		accinfo.datasz = cnt;
		payloadpos += iap_buildfidtokenatbuf(&(payload[payloadpos]), &accinfo);
	}

// EAProtocolToken
	{
		fidtoken_t eaprotocol;
		unsigned char const protocolstring[] = MFI_PROTOCOL_STRING;
		unsigned char eapprotocoldata[1 + sizeof(protocolstring)];
		cnt = 0;
		eaprotocol.type = 0;
		eaprotocol.subtype = 4;

		// protocol index = 1
		eapprotocoldata[0] = 1;
		memcpy(&(eapprotocoldata[1]), protocolstring, sizeof(protocolstring));
		eaprotocol.data = eapprotocoldata;
		eaprotocol.datasz = sizeof(eapprotocoldata);
		payloadpos += iap_buildfidtokenatbuf(&(payload[payloadpos]),
				&eaprotocol);
	}

// BundleSeedIdPrefToken
	{
		fidtoken_t bundleseedidpref;
		unsigned char const bundleseedidprefstring[] = MFI_BUNDLE_SEED_ID;
		unsigned char bundleseedidprefdata[sizeof(bundleseedidprefstring)];
		cnt = 0;
		bundleseedidpref.type = 0;
		bundleseedidpref.subtype = 5;
		memcpy(&(bundleseedidprefdata[0]), bundleseedidprefstring,
				sizeof(bundleseedidprefstring));
		bundleseedidpref.data = bundleseedidprefdata;
		bundleseedidpref.datasz = sizeof(bundleseedidprefdata);
		payloadpos += iap_buildfidtokenatbuf(&(payload[payloadpos]),
				&bundleseedidpref);
	}
	iap_build_packet_and_send(payload, payloadpos, 0, IAP_MSG_SETFIDTOKENVALUES,
			iap_getnextoutgoingtransactionid(), TRUE, TRUE);
}

/**
 * sends the StartIDPS packet via IAP
 *
 * sends the StartIDPS packet via IAP
 */
static void iap_sendStartIdps(void) {
	iap_build_packet_and_send(NULL, 0, 0, IAP_MSG_STARTIDPS,
			iap_getnextoutgoingtransactionid(), TRUE, TRUE);
}

/**
 * sends the RequestTransportMaxPayloadSize packet via IAP
 *
 * sends the RequestTransportMaxPayloadSize packet via IAP
 */
static void iap_sendRequestTransportMaxPayloadSize(void) {
	iap_build_packet_and_send(NULL, 0, 0,
			IAP_MSG_REQUESTTRANSPORTMAXPAYLOADSIZE,
			iap_getnextoutgoingtransactionid(), TRUE, TRUE);
}

/**
 * sends the AccessoryAck packet via IAP
 *
 * sends the AccessoryAck packet via IAP
 *
 * @param cmdid:  command ID to indicate within AccessoryAck message
 * @param status:  status to indicate within AccessoryAck message
 */
static void iap_sendAccessoryAck(unsigned char cmdid, unsigned char status) {
	unsigned char payload[2];
	payload[0] = status;
	payload[1] = cmdid;
	iap_build_packet_and_send(payload, 2, 0, IAP_MSG_ACCESSORYACK,
			usbiap_incomingtransactionid, TRUE, FALSE);
}

/**
 * sends the RetAccessoryAuthenticationSignature packet with signature data via IAP
 *
 * sends the RetAccessoryAuthenticationSignature packet via IAP.  embeds the specified
 * signature data in the packet.
 *
 * @param sigbuf:  buffer containing signature data
 * @param siglen:  length of signature data
 */
static void iap_setRetAccessoryAuthenticationSignature(unsigned char *sigbuf,
		int siglen) {
	iap_build_packet_and_send(sigbuf, siglen, 0,
			IAP_MSG_RETACCESSORYAUTHENTICATIONSIGNATURE,
			usbiap_incomingtransactionid, TRUE, TRUE);
}

/**
 * sends the RequestApplicationLaunch packet via IAP
 *
 * sends the RequestApplicationLaunch packet via IAP.  embeds the specified
 * application bundle name in the packet.
 *
 * @param appbundleid:  buffer containing bundle ID
 * @param len:  length of bundle ID
 */
static void iap_sendRequestApplicationLaunch(unsigned char *appbundleid,
		int len) {
	unsigned char *payload = malloc(len + 3);

	payload[0] = 0;
	payload[1] = 2;
	payload[2] = 0;
	memcpy(&(payload[3]), appbundleid, len);
	iap_build_packet_and_send(payload, len + 3, 0,
			IAP_MSG_REQUESTAPPLICATIONLAUNCH,
			iap_getnextoutgoingtransactionid(), TRUE, TRUE);
	free(payload);
}

/**
 * sends the RetDevAuthenticationInfo packet via IAP
 *
 * sends the RetDevAuthenticationInfo packet via IAP.  embeds the specified
 * authentication certificate in the packet.
 *
 * @param certbuf:  buffer containing certificate
 * @param certlen:  length of certificate
 */
static void iap_sendRetDevAuthenticationInfo(unsigned char *certbuf,
		int certlen) {
	int maxsize = 400; //iap_maxpayloadsize - 8;
	int maxsectionidx = (certlen / maxsize);
	unsigned char *payload;
	int i = 0;
	int tocopy;
	int cnt;

	while (i < certlen) {
		tocopy = certlen - i;
		if ((certlen - i) > maxsize) {
			tocopy = maxsize;
		}
		payload = malloc(tocopy + 6);
		cnt = 0;
		payload[cnt++] = 2; // auth major version 2
		payload[cnt++] = 0; // auth minor version 0
		payload[cnt++] = i / maxsize; // section index
		payload[cnt++] = maxsectionidx; // maximum section index
		memcpy(&(payload[cnt]), &(certbuf[i]), tocopy);
		i += tocopy;
		cnt += tocopy;
		iap_build_packet_and_send(payload, cnt, 0,
				IAP_MSG_RETDEVAUTHENTICATIONINFO, usbiap_incomingtransactionid,
				TRUE, TRUE);
		free(payload);
	}
}

/**
 * sends the EndIDPS packet via IAP
 *
 * sends the EndIDPS packet via IAP
 */
static void iap_sendEndIDPS(void) {
	unsigned char payload;
	payload = 0;
	iap_build_packet_and_send(&payload, 1, 0, IAP_MSG_ENDIDPS,
			iap_getnextoutgoingtransactionid(), TRUE, TRUE);
}

/**
 * sends the DevDataTransfer packet via IAP
 *
 * sends the DevDataTransfer packet via IAP.  embeds the specified
 * data in the packet.
 *
 * @param buf:  buffer containing data
 * @param len:  length of data
 */
static void iap_sendDevDataTransfer(int sessionid, char *buf, int len) {
	unsigned char *payload;

	payload = (unsigned char *) malloc(len + 2);
	payload[0] = sessionid / 256;
	payload[1] = sessionid & 0xFF;
	memcpy(&(payload[2]), buf, len);
	iap_build_packet_and_send(payload, len + 2, 0, IAP_MSG_DEVDATATRANSFER,
			iap_getnextoutgoingtransactionid(), TRUE, TRUE);
	free(payload);
}

/**
 * processes the received ReturnTransportMaxPayloadSize iAP packet
 *
 * stores the included maxpayload size for use in constructing packets
 *
 * @param databuf:  pointer to packet payload starting with transaction ID
 * @param datalen:  length of payload
 */
static void usb_iap_processReturnTransportMaxPayloadSize(unsigned char *databuf,
		int datalen) {
	iap_maxpayloadsize = (databuf[2] * 256) + databuf[3];
	iap_requestmaxpayloadsizereceived = TRUE;
	iphoned_log(IPHONEDLOG_INFO, "iap maxpayloadsize = %d", iap_maxpayloadsize);
}

/**
 * indicates the current status of the ACK-wait structure
 *
 * returns status of ACK-wait structure.  primary indicator is ackwait.received.  If
 * not received, function determines whether there has been an ack timeout.
 *
 * @return ACKSTATUS_RECEIVED, ACKSTATUS_WAITING or ACKSTATUS_TIMEOUT
 */
static int iap_ack_status(void) {
	time_t now;

	time(&now);
	if (ackwait.received == TRUE) {
		return ACKSTATUS_RECEIVED;
	} else {
		if (difftime(now, ackwait.starttime) < ackwait.timeoutsec) {
			return ACKSTATUS_WAITING;
		}
		return ACKSTATUS_TIMEOUT;
	}
}

static void iap_processack(unsigned char *databuf, int datalen) {
	int transactionid;
	unsigned char ackcmdid = (int) databuf[1];
	unsigned char result = (int) databuf[0];

	if (datalen == 2) {
		result = (int) databuf[0];
		ackcmdid = (int) databuf[1];
	} else if (datalen == 4) {
		transactionid = databuf[0] * 256;
		transactionid += databuf[1];
		result = (int) databuf[2];
		ackcmdid = (int) databuf[3];
	}

	if (iap_ack_status() == ACKSTATUS_WAITING) {
		if ((ackcmdid == ackwait.cmdid)
				&& (transactionid == ackwait.transactionid)
				&& (result == ackwait.expectedresult)) {
			ackwait.received = TRUE;
		}
	}
}

/**
 * Processes the iPodDataTransfer message
 *
 * processes the iPodDataTransfer message by forwarding the given data to the connecting
 * application if the session ID matches the current session ID.  if not, sends an ACK with
 * ackstatus noting bad parameter
 *
 * @param buf:  pointer to packet payload starting with transaction ID
 * @param len:  length of payload
 */
static void iap_processiPodDataTransfer(unsigned char *buf, int len) {
	int sessionid;

	sessionid = (buf[2] * 256) + buf[3];
	if ((sessionid == iap_opensessionid) && (iap_isappsessionopen() == TRUE)) {
		iap_sendAccessoryAck(IAP_MSG_IPODDATATRANSFER, 0x00);
		server_forwardapplicationdata(&(buf[4]), len - 4);
	} else {
		iap_sendAccessoryAck(IAP_MSG_IPODDATATRANSFER, 0x04);
	}
}

/**
 * Processes the RequestIdentify message
 *
 * processes the requestidentifymessage by resetting the IAP state machine
 * (and not resetting the packet parser)
 * @param buf:  pointer to packet payload starting with transaction ID
 * @param len:  length of payload
 */
static void iap_processRequestIdentify(unsigned char *buf, int len) {
	iapstate = IPHONESTATE_JUSTCONNECTED;
}

/**
 * Processes the AckDevAuthentcationInfo message
 *
 * processes the AckDevAuthentcationInfo by setting a state variable to
 * cause the state machine to advance
 *
 * @param buf:  pointer to packet payload starting with transaction ID
 * @param len:  length of payload
 */
static void iap_processAckDevAuthentcationInfo(unsigned char *buf, int len) {
	if (buf[2] == 0x00) {
		iap_certificateaccepted = TRUE;
	}
}

/**
 * Processes the GetAccessoryAuthenticationSignature message
 *
 * processes the GetAccessoryAuthenticationSignature by storing the signature
 * challenge and setting a state variable to cause the state machine to advance
 *
 * @param buf:  pointer to packet payload starting with transaction ID
 * @param len:  length of payload
 */
static void iap_processGetAccessoryAuthenticationSignature(unsigned char *buf,
		int len) {
	authchallengelen = len - 3;
	if (authchallengelen <= sizeof(authchallenge)) {
		memcpy(authchallenge, &(buf[2]), authchallengelen);
		iap_authchallengereceived = TRUE;
	}
}

/**
 * Processes the AckAccessoryAuthenticationStatus message
 *
 * processes the AckAccessoryAuthenticationStatus by setting a state variable to
 * cause the state machine to advance
 *
 * @param buf:  pointer to packet payload starting with transaction ID
 * @param len:  length of payload
 */
static void iap_processAckAccessoryAuthenticationStatus(unsigned char *buf,
		int len) {
	if (buf[2] == 0x00) {
		iap_authentcationstatusok = TRUE;
	}
}

/**
 * Processes the OpenDataSessionForProtocol message
 *
 * processes the OpenDataSessionForProtocol by storing the session ID and setting
 * a state variable to cause the state machine to advance
 *
 * @param buf:  pointer to packet payload starting with transaction ID
 * @param len:  length of payload
 */
static void iap_processOpenDataSessionForProtocol(unsigned char *buf, int len) {
	int sessionid = (buf[2] * 256) + buf[3];
	iap_opensessionid = sessionid;

	if (buf[4] == 1) {
		iap_sendAccessoryAck(IAP_MSG_OPENDATASESSIONFORPROTOCOL, 0x00);
		iap_sessionopen = TRUE;
	} else {
		iap_sendAccessoryAck(IAP_MSG_OPENDATASESSIONFORPROTOCOL, 0x04);
	}
}

/**
 * Processes the CloseDataSession message
 *
 * processes the CloseDataSession by invalidating the session ID and setting
 * a state variable to cause the state machine to advance
 *
 * @param buf:  pointer to packet payload starting with transaction ID
 * @param len:  length of payload
 */
static void iap_processCloseDataSession(unsigned char *buf, int len) {
	iap_sessionopen = FALSE;
	iap_opensessionid = -1;
	iap_sendAccessoryAck(IAP_MSG_CLOSEDATASESSION, 0x00);
}

/**
 * sets the device ID to be set during iAP authentication process
 *
 * stores the provided device ID as a variable to be used during the iAP
 * authentication process.
 *
 * @param deviceid:  numeric form of device ID  (eventually a 16-bit value)
 */
void iap_setDeviceID(int deviceid) {
	iap_deviceid = deviceid;
}

/**
 * sets the MFI authentication certificate to be used during iAP authentication
 *
 * copies the provided buffer to the certification buffer which is used during iAP
 * authentication
 *
 * @param certbuf:  pointer to source certificate buffer
 * @param certlen:  length of certificate
 */
void iap_setcertificate(unsigned char *certbuf, int certlen) {
	memcpy(iap_auth_cert, certbuf, certlen);
	iap_auth_cert_len = certlen;
}

/**
 * queries if action is pending in the iAP state machine
 *
 * checks indicators of pending iAP state machine action and returns TRUE or FALSE.
 * Intended to allow for different call timeouts.
 *
 * @return TRUE if action is pending, FALSE otherwise
 */
int iap_is_pending_action(void) {
	if (((iap_ack_status() == ACKSTATUS_RECEIVED)
			|| (iap_ack_status() == ACKSTATUS_TIMEOUT))
			&& (iapstate != IPHONESTATE_AUTHENTICATED_SESSIONOPEN_READY)) {
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * returns absolute maximum size for data sent via iap_presentdatafortransfer()
 *
 * transaction id = 2 bytes
 * session id = 2 bytes
 * command id = 1 byte
 * lingo id = 1 byte
 *
 * @return number of bytes allowed to be passed to iap_presentdatafortransfer
 */
int iap_get_max_data_sz(void) {
	return iap_maxpayloadsize - 6;
}

/**
 * determines if iAP state machine is ready to send data to the iPhone application
 *
 * this is simply based on state machine state.  if we are in the connected state,
 * and not waiting on an ACK for previous data, returns TRUE
 *
 * @return TRUE if iAP is ready to send data.  FALSE otherwise.
 */
int iap_isreadyfordata(void) {
	if (iapstate == IPHONESTATE_AUTHENTICATED_SESSIONOPEN_READY) {
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * sends data to iPhone application if ready and size is acceptable
 *
 * this is simply based on state machine state.  if we are in the connected state,
 * returns TRUE
 *
 * @param buf:  pointer to buffer with data to be sent
 * @param len:  length of data to be sent
 */
void iap_presentdatafortransfer(unsigned char *buf, int len) {
	if ((iap_isreadyfordata() == TRUE) && (len <= iap_get_max_data_sz())) {
		// check if connected and previous data has been ACKed
		iapstate = IPHONESTATE_AUTHENTICATED_SESSIONOPEN_WAIT;
		iap_sendDevDataTransfer(iap_opensessionid, buf, len);
	}
}

/**
 * determines if application session is open.
 *
 * determines if application session is open.  used to notify connecting client that
 * connection is established
 *
 * @return TRUE if application session is open.  FALSE otherwise.
 */
int iap_isappsessionopen(void) {
	if ((iapstate == IPHONESTATE_AUTHENTICATED_SESSIONOPEN_READY)
			|| (iapstate == IPHONESTATE_AUTHENTICATED_SESSIONOPEN_WAIT)) {
		return TRUE;
	}
	return FALSE;
}

/**
 * forces ackwait structure to be in the 'received' position
 *
 * to deal with situations where iPodAck is not used as a response message, we use this
 * to trigger the ackwait structure, ensuring that an ack timeout doesn't occur.
 */
static void iap_forceackreceived(void) {
	ackwait.received = TRUE;
}

