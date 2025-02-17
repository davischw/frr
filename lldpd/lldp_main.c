// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LLDP daemon code.
 * Copyright (c) 2016 zhurish
 * Copyright (c) 2025 Network Device Education Foundation (NetDEF), Inc.
 */


#include <zebra.h>

#include "lib/version.h"
#include "getopt.h"
#include "frr_pthread.h"
#include "memory.h"
#include "if.h"
#include "sigevent.h"
#include "log.h"
#include "privs.h"
#include "zclient.h"

/*
#include "prefix.h"
#include "linklist.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "filter.h"
#include "plist.h"
#include "stream.h"
*/

#include "lldpd.h"
#include "lldp_interface.h"

/*
#include "lldp_neighbor.h"
#include "lldp_db.h"
#include "lldp_packet.h"
#include "lldp_socket.h"
*/


/* Master of threads. */
struct event_loop *master;


/* LLDPd privileges. */
static zebra_capabilities_t _caps_p[] = {
	ZCAP_NET_RAW,
	ZCAP_BIND,
	ZCAP_NET_ADMIN
};


struct zebra_privs_t lldp_privs = {
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

/* LLDP daemon information. */
static struct frr_daemon_info lldpd_di;


struct option longopts[] = {};
/* TODO: longopts
struct option longopts[] = {
	{ "daemon", no_argument, NULL, 'd' },
	{ "config_file", required_argument, NULL, 'f' },
	{ "pid_file", required_argument, NULL, 'i' },
	{ "socket", required_argument, NULL, 'z' },
	{ "help", no_argument, NULL, 'h' },
	{ "vty_addr", required_argument, NULL, 'A' },
	{ "vty_port", required_argument, NULL, 'P' },
	{ "user", required_argument, NULL, 'u' },
	{ "group", required_argument, NULL, 'g' },
	{ "version", no_argument, NULL, 'v' },
	{ 0 }
};
*/


/* Help information display. */
/* TODO: replaced by frr_help_exit
static void __attribute__((noreturn)) usage(char *progname, int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n", progname);
	else {
		printf("Usage : %s [OPTION...]\n\
Daemon which manages LLDPD.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-i, --pid_file     Set process identifier file name\n\
-z, --socket       Set path of zebra socket\n\
-A, --vty_addr     Set vty's bind address\n\
-P, --vty_port     Set vty's port number\n\
-u, --user         User to run as\n\
-g, --group        Group to run as\n\
-v, --version      Print program version\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n",
		       progname, ZEBRA_BUG_ADDRESS);
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

	lldp_zebra_terminate();

	lldp_interface_terminate();

	frr_fini();

	exit(0);
}


/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}


struct frr_signal_t lldp_signals[] = {
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


/* TODO: yang modules? */


/* clang-format off */
FRR_DAEMON_INFO(lldpd, LLDP,
	.vty_port = LLDP_VTY_PORT,
	.proghelp = "Implementation of the link layer discovery protocol.",

	.signals = lldp_signals,
	.n_signals = array_size(lldp_signals),

	.privs = &lldp_privs,

	/* TODO: yang?
	.yang_modules = lldpd_yang_modules,
	.n_yang_modules = array_size(lldpd_yang_modules),
	*/
);
/* clang-format on */



int main(int argc, char **argv)
{
	/* TODO: replace vars with config
	char *p;
	char *vty_addr = NULL;
	int vty_port = LLDP_VTY_PORT;
	int daemon_mode = 0;
	char *config_file = NULL;
	char *progname;
	struct thread thread;
	*/

	/* TODO: check if needed: */
	/* Set umask before anything for security */
	/*
	umask(0027);
	*/

	/* get program name */
	/*progname = ((p = strrchr(argv[0], '/')) ? ++p : argv[0]);*/

	frr_preinit(&lldpd_di, argc, argv);
	frr_opt_add("", longopts, "");

	while (1) {
		int opt;

		/* TODO: longopts
		opt = getopt_long(argc, argv, "df:i:z:hA:P:u:g:av");
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
		case 'i':
			pid_file = optarg;
			break;
		case 'z':
			zclient_serv_path_set(optarg);
			break;
		case 'P':
			if (strcmp(optarg, "0") == 0) {
				vty_port = 0;
				break;
			}
			vty_port = atoi(optarg);
			if (vty_port <= 0 || vty_port > 0xffff)
				vty_port = LLDP_VTY_PORT;
			break;
		case 'u':
			lldp_privs.user = optarg;
			break;
		case 'g':
			lldp_privs.group = optarg;
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

	/* Invoked by a priviledged user? -- endo. */
	/* TODO: check if needed
	if (geteuid() != 0) {
		errno = EPERM;
		perror(progname);
		exit(1);
	}
	*/

	/* TODO: check how to replace
	zlog_default = openzlog(progname, ZLOG_LLDP, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);
	*/

	master = frr_init();

	/*
	*//* Library inits. *//*
	zprivs_init(&lldp_privs);
	signal_init(master, array_size(lldp_signals), lldp_signals);
	cmd_init(1);
	*/

	/*
	 * vty_init(master);
	 */
	lldp_vty_init();

	/*
	memory_init();

	lldp_config_init();
	*/

	lldp_interface_init();

	lldp_zebra_init();

	/* Get configuration file. *//*
	vty_read_config(config_file, config_default);

	*//* Change to the daemon program. *//*
	if (daemon_mode && daemon(0, 0) < 0) {
		zlog_err("LLDPd daemon failed: %s", strerror(errno));
		exit(1);
	}

	*//* Process id file create. *//*
	pid_output(pid_file);

	*//* Create VTY socket *//*
	vty_serv_sock(vty_addr, vty_port, LLDP_VTYSH_PATH);

	*//* Print banner. *//*
	zlog_notice("LLDPd %s starting: vty@%d", QUAGGA_VERSION, vty_port);

	*//* Get configuration file. *//*
	lldp_vty_init();
	*/

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return (0);
}
