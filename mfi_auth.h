//******************************************************************************
//******************************************************************************
//
// FILE:        mfi_auth.h
//
// DESCRIPTION: header file for mfi_auth.c to access library API
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
#ifndef MFI_AUTH_H_
#define MFI_AUTH_H_

#define AUTH_CERT_MAX_SZ 1920
#define AUTHCHALLENGERESPONSE_MAX_SZ 128

int mfi_auth_init(void);
void mfi_auth_close(void);
int mfi_auth_get_cert_and_length(unsigned char *buf, unsigned int *len);
int mfi_auth_processchallenge(unsigned char *challengebuf, int challengelen, unsigned char *responsebuf, int *responselen);

#endif /* MFI_AUTH_H_ */
