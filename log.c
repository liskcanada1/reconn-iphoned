//******************************************************************************
//******************************************************************************
//
// FILE:        log.c
//
// DESCRIPTION: implements logging for iphoned
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <syslog.h>

#include "log.h"
#include "iphoned.h"

static int log_level = IPHONEDLOG_FATAL;

static int log_syslog = 0;
static int first_run = TRUE;

/**
 * convert internal loglevel to syslog loglevel
 *
 * converts the passed in internal log level to the appropriate syslog loglevel
 *
 * @param level:  loglevel to convert
 *
 * @return equivalent syslog loglevel
 */
static int level_to_syslog_level(int level) {
	int result = level + LOG_CRIT;
	if (result > LOG_DEBUG) {
		result = LOG_DEBUG;
	}
	return result;
}

/**
 * resolves the provided print spec and logs writes to syslog and to stderr
 *
 * converts the passed in internal log level to the appropriate syslog loglevel.
 * log levels lower than the set minimum will be tossed out.
 *
 * @param level:  loglevel to use for log entry
 */
void iphoned_log(enum loglevel level, const char *fmt, ...) {
	va_list ap;
	char *fs;
	struct timeval ts;
	struct tm *tp;

	if (first_run == TRUE) {
		first_run = FALSE;
		openlog("iphoned", LOG_PID, 0);
		log_syslog = 1;
	}

	if (level > log_level) {
		return;
	}
	gettimeofday(&ts, NULL);
	tp = localtime(&ts.tv_sec);
	fs = malloc(20 + strlen(fmt));
	if (log_syslog) {
		sprintf(fs, "%d.%03d[%d] %s\n", (int)ts.tv_sec, (int)(ts.tv_usec / 1000), level, fmt);
	}
	va_start(ap, fmt);
	vsyslog(level_to_syslog_level(level), fs, ap);
	vfprintf(stderr, fs, ap);
	va_end(ap);
	free(fs);
}

/**
 * sets minimum log level to record
 *
 * sets the minimum log level to record.  log levels lower than this value will not be
 * recorded
 *
 * @param loglevel:  minimum loglevel
 */
void log_setlevel(int loglevel) {
	log_level = loglevel;
}
