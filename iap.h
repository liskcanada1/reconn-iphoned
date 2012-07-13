//******************************************************************************
//******************************************************************************
//
// FILE:        iap.h
//
// DESCRIPTION: header file for iap.c to access library API
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
#ifndef IAP_H_
#define IAP_H_

#define MFI_ACCESSORY_NAME "Reconn Mobile SATCOM Toolkit"
#define MFI_MANUFACTURER_NAME "Harris Corporation"
#define MFI_MODEL_NUMBER "39574-1100-00"
#define MFI_FIRMWARE_VERSION 1000
#define MFI_HARDWARE_VERSION 1000
#define MFI_PROTOCOL_STRING "com.coolfiresolutions.reconn100"
#define MFI_BUNDLE_SEED_ID "5MSPW6C8UC"
#define MFI_APP_STARTUP_BUNDLE_NAME "com.coolfiresolutions.cfsreconn"

void iap_reset_connection(void);
void iap_parsestream(unsigned char *buf, int len);
void iap_setDeviceID(int deviceid);
void iap_setcertificate(unsigned char *certbuf, int certlen);
int iap_is_pending_action(void);
int iap_get_max_data_sz(void);
int iap_isreadyfordata(void);
void iap_presentdatafortransfer(unsigned char *buf, int len);
int iap_isappsessionopen(void);
int iap_process_state(void);
#endif /* IAP_H_ */
