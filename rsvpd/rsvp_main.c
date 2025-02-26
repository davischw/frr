/* Main Routine of rsvpd.
   Copyright (C) 2003,05 Pranjal Kumar Dutta

This file is part of GNU zMPLS.

GNU zMPLS is free software; you can redistribute it and/or modify it
user the terms of the GNU General Public License as published by the 
Free Software Foundation; either version 2,  or (at your option) any
later version.

GNU zMPLS is distributed in the hope that it will be useful, but 
WITHOUT ANY WARRANTY; without even the implied warranry of 
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING. If not, write to the Free
Software Foundation, Inc..59 Temple Place - Suite 330, Boston, MA
02111-1307, USA. */

#include <zebra.h>

#include "frrevent.h"
#include "getopt.h"
#include "libfrr.h"
#include "lib/version.h"
#include "log.h"
#include "prefix.h"
#include "privs.h"
#include "sigevent.h"

/*
#include "linklist.h"
#include "version.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "thread.h"
#include "version.h"
#include "memory.h"
#include "sockunion.h"
#include "if.h"
#include "lsp.h"
#include "stream.h"
#include "zclient.h"
#include "avl.h"
*/

#include "rsvpd/rsvpd.h"
#include "rsvpd/rsvp_zebra.h"
#include "rsvpd/rsvp_vty_example.h"

/*
//#include "rsvpd/config.h"
*/


/* Master of threads. */
struct event_loop *master;


/* RSVPd privileges. */
static zebra_capabilities_t _caps_p[] = {};

struct zebra_privs_t rsvp_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
        .user = FRR_USER,
        .group = FRR_GROUP,
#endif
#if defined(VTY_GROUP)
        .vty_group = VTY_GROUP,
#endif
        .caps_p = _caps_p,
        .cap_num_p = array_size(_caps_p),
        .cap_num_i = 0
};


/* RSVPd daemon information. */
static struct frr_daemon_info rsvpd_di;


/* RSVPd options, we use GNU getopt library. */
struct option longopts[] = {};
/*
struct option longopts[] = { { "daemon", no_argument, NULL, 'd' },
			     { "config_file", required_argument, NULL, 'f' },
			     { "pid_file", required_argument, NULL, 'i' },
			     { "ldp_port", required_argument, NULL, 'p' },
			     { "vty_addr", required_argument, NULL, 'A' },
			     { "vty_port", required_argument, NULL, 'P' },
			     { "retain", no_argument, NULL, 'r' },
			     { "no_kernel", no_argument, NULL, 'n' },
			     { "version", no_argument, NULL, 'v' },
			     { "help", no_argument, NULL, 'h' },
			     { 0 } };
*/

/*
*//* Configuration file and directory. *//*
//char config_current[] = RSVPD_DEFAULT_CONFIG;
char config_default[] = SYSCONFDIR RSVPD_DEFAULT_CONFIG;

*//* Route retain mode flag. *//*
int retain_mode = 0;
*/



/*
*//* Manually Specified configuration file name. *//*
char *config_file = NULL;

*//* Process ID saved for use by init system *//*
char *pid_file = PATH_RSVPD_PID;

*//* VTY port number and address. *//*
int vty_port = RSVPD_VTY_PORT;
char *vty_addr = NULL;

*//* Help information dispaly. *//*
static void usage(char *progname, int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help` for more information.\n", progname);
	else {
		printf("Usage : %s [OPTION...]\n\n\
Daemon for RSVP-TE (RFC 3209) and it interacts with zMPLS daemon for programming the TE-LSP data paths into MPLS Forwarding Engine in the kernel. \n\n\
-d, --daemon		Runs in daemon mode\n\
-f, --config_file       Set configuration file name\n\
-i, --pid_file          Set process identifier file name\n\
-p, --ldp_port		Set ldp protocol's port number\n\
-A, --vty_addr		Set vty's bind address\n\
-P, --vty_port		Set vty's port number\n\
-r, --retain            When program terminates retain added LSPs by ldpd. \n\
-n, --no_kernel		Do not install route to kernel.\n\
-v, --version		Print program version\n\
-h, --help		Dispaly this hlp and exit\n\
\n\
Report bugs to %s\n",
		       progname, "127.0.0.1");
	}

	exit(status);
}
*/


/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received");
}


/* SIGINT / SIGTERM handler. */
static void sigint(void)
{
	zlog_notice("Terminating on signal");

	rsvp_zebra_terminate();

	frr_fini();

	exit(0);
}


/* SIGUSR1 handler. */
static void sigusr1(void)
{
        zlog_rotate();
}


struct frr_signal_t rsvp_signals[] = {
        {
                .signal = SIGHUP,
                .handler = &sighup,
        },
        {
                .signal = SIGUSR1,
                .handler = &sigusr1,
        },
        {
                .signal = SIGINT,
                .handler = &sigint,
        },
        {
                .signal = SIGTERM,
                .handler = &sigint,
        },
};


/* clang-format off */
FRR_DAEMON_INFO(rsvpd, RSVP,
        .vty_port = RSVPD_VTY_PORT,
        .proghelp = "Implementation of the resource reservation protocol.",

        .signals = rsvp_signals,
        .n_signals = array_size(rsvp_signals),

        .privs = &rsvp_privs,
);
/* clang-format on */


/* Main routine of ldpd. Treatment of argument and start ldp finite
   state machine is handled at here. */
int main(int argc, char **argv)
{
	/*
	char *p;
	int daemon_mode = 0;
	char *progname;
	struct thread thread;

	*//* Set umask before anything for security *//*
	umask(0027);

	*//* Preserve name for myself. *//*
	progname = ((p = strchr(argv[0], '/')) ? ++p : argv[0]);

	zlog_default = openzlog(progname, ZLOG_RSVP, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);

	//host_name = "RSVP-TE";
	*//* LDP master init. *//*
	rsvp_master_init();
	*//* Debug *//*
	printf("[rsvpd] rsvp_master initialized\n");
	*/

	frr_preinit(&rsvpd_di, argc, argv);
	frr_opt_add("", longopts, "");

	/* Command line argument treatment. */
	while (1) {
		int opt;

		/*
		opt = getopt_long(argc, argv, "df:hP:A:P:rnv", longopts, 0);
		*/

		opt = frr_getopt(argc, argv, NULL);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		/*
		case 'd':
			daemon_mode = 1;
			break;
		case 'f':
			config_file = optarg;
			break;
		case 'A':
			vty_addr = optarg;
			break;
		case 'P':
			vty_port = atoi(optarg);
			break;
		case 'r':
			retain_mode = 1;
			break;
		case 'n':
			*//*ldp_option_set (LDP_OPT_NO_FIB);*//*
			break;
		case 'v':
			print_version(progname);
			exit(0);
			break;
		case 'h':
			usage(progname, 0);
			break;
		*/
		default:
			frr_help_exit(1);
			break;
		}
	}

	/* Make Thread Master. */
	master = frr_init();

	/* Initialization. */
	/*
	srand(time(NULL));
	signal_init();
	cmd_init(1);
	vty_init(master);
	memory_init();

	*//* RSVP Related Initialization. *//*
	rsvp_init();
	*/

	rsvp_vty_example_init();

	rsvp_zebra_init();

	/*
	*//* Sort CLI Commands. *//*
	//sort_node ();

	*//* Parse config file. *//*
	vty_read_config(config_file, config_default);

	*//* Turn into daemon if daemon_mode is set  *//*
	if (daemon_mode)
		daemon(0, 0);

	*//* Process ID File Creation. *//*
	pid_output(pid_file);

	*//* Make ldp vty socket. *//*
	vty_serv_sock(vty_addr, vty_port, RSVP_VTYSH_PATH);

	*//* Print Banner. *//*
	zlog_notice("RSVPd %s starting: vty@%d", QUAGGA_VERSION, vty_port);

	*//* Set that RSVP is initialization is complete.*//*
	rsvp_init_set_complete();
	*//* Start finite state machine, here we go! *//*
	while (thread_fetch(master, &thread))
		thread_call(&thread);
	*/

	frr_config_fork();
	frr_run(master);

	/* Not Reached. */
	return 0;
}
