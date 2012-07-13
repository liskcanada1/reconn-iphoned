//******************************************************************************
//******************************************************************************
//
// FILE:        iphoned.c
//
// DESCRIPTION: iphoned application entry/exit functions, signal handler and
//					fatal error handling
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
#include <stdlib.h>
#include <signal.h>
#include <semaphore.h>

#include "log.h"
#include "usb.h"
#include "iphoned.h"
#include "server.h"

#define IPHONED_CONSOLE_DEBUG

static int terminatemainloop = FALSE;
static sem_t apptermsem;

static void daemonize(void);
static void sig_handler(int signum);

/**
 * process signal handler
 *
 * function to handle all process signals.  all signals are handled the same - terminate the
 * application
 *
 * @param signum:  signal number
 */
static void sig_handler(int signum) {
	static int handled = FALSE;

	if (handled == FALSE) {
		iphoned_log(IPHONEDLOG_DEBUG, "Received signal %d\n", signum);
		terminatemainloop = TRUE;
		handled = TRUE;
		sem_post(&apptermsem);
	}
}

/**
 * causes execution of application as a daemon and redirects STDIO
 *
 * daemonization causes the application to be forked with the parent PID = 1.
 * in addition, STDIO is redirected to not clutter console.
 */
static void daemonize(void) {
	pid_t pid, sid;

	// we're already a daemon
	if (getppid() == 1)
		return;

	// fork the parent process
	pid = fork();
	if (pid < 0) {
		exit(-1);
	}

	// exit the parent process
	if (pid > 0) {
		exit(0);
	}

	// now we are the child
	umask(0);

	sid = setsid();
	if (sid < 0) {
		exit(1);
	}

	// prevent cwd from being locked
	if ((chdir("/")) < 0) {
		exit(1);
	}

#ifndef IPHONED_CONSOLE_DEBUG
	// redirect standard files
	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);
#endif
}

/**
 * handles unrecoverable errors
 *
 * shuts down application immediately.
 *
 * @param filename:  notes file name of source code generating error
 * @param lineno:  notes line number of source code generating error
 * @param arg:  argument with more error information
 */
void fatal_shutdown(unsigned char *filename, int lineno, int arg) {
	iphoned_log(IPHONEDLOG_FATAL, "FATAL at %s:%d arg %d", filename, lineno,
			arg);
	exit(-99);
}

/**
 * application entry point
 *
 * shuts down application immediately.
 *
 * @param argc:  number of arg strings
 * @param argv:  array of arg string pointers
 */
int main(int argc, char *argv[]) {
	int res;

	daemonize();
	signal(SIGINT, sig_handler);
	res = sem_init(&apptermsem, 0, 0);
	if (res != 0) {
		iphoned_log(IPHONEDLOG_NOTICE, "Failed to get terminate semaphore.");
		return res;
	}
	res = server_start();
	if (res != 0) {
		iphoned_log(IPHONEDLOG_NOTICE, "Failed to start server");
		return res;
	}
	res = usb_start();
	if (res != 0) {
		iphoned_log(IPHONEDLOG_NOTICE, "Failed to start USB");
		return res;
	}
	sem_wait(&apptermsem);
	iphoned_log(IPHONEDLOG_NOTICE, "Shutting down");
	server_stop();
	usb_stop();
	return 0;
}

