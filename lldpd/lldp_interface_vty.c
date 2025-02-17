/*
 * lldp_interface.c
 *
 *  Created on: Oct 24, 2016
 *      Author: zhurish
 */

#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "table.h"
#include "stream.h"
#include "memory.h"
#include "routemap.h"
#include "zclient.h"
#include "log.h"

#include "lldpd.h"
#include "lldp_interface.h"
#include "lldp_db.h"
#include "lldp_packet.h"
#include "lldp_socket.h"


DEFUN (lldpd_enable,
		lldpd_enable_cmd,
	    "lldp enable",
		LLDP_STR
		"enable lldp\n")
{
	struct interface *ifp = NULL;
	struct lldp_interface *lifp = NULL;
	ifp = vty->index;
	if (ifp)
		lifp = ifp->info;
	if (lifp == NULL)
		return CMD_WARNING;
	lifp->mode = LLDP_ENABLE; /* 使能状态 */
	return lldp_interface_enable(ifp);
}
DEFUN (no_lldpd_enable,
		no_lldpd_enable_cmd,
	    "no lldp enable",
		NO_STR
		LLDP_STR
		"enable lldp\n")
{
	struct interface *ifp = NULL;
	struct lldp_interface *lifp = NULL;
	ifp = vty->index;
	if (ifp)
		lifp = ifp->info;
	if (lifp == NULL)
		return CMD_WARNING;
	lifp->mode = LLDP_DISABLE; /* 使能状态 */
	return lldp_interface_disable(ifp);
}

#ifdef LLDP_PROTOCOL_DEBUG
#define LLDP_PROTOCOL " (compliance) (cdp|edp|fdp|sonmp|lldp-med|custom)"
#define LLDP_PROTOCOL_HELP                                                                         \
	"lldpd compliance witch config\n"                                                          \
	"compliance cdp protocol enable\n"                                                         \
	"compliance edp protocol enable\n"                                                         \
	"compliance fdp protocol enable\n"                                                         \
	"compliance sonmp protocol enable\n"                                                       \
	"compliance lldp-med protocol enable\n"                                                    \
	"compliance custom protocol enable\n"
#else
#define LLDP_PROTOCOL	   ""
#define LLDP_PROTOCOL_HELP ""
#endif

DEFUN (lldpd_receive,
		lldpd_receive_cmd,
	    "lldp receive",
		LLDP_STR
		"lldpd receive enable\n")
{
	struct interface *ifp = NULL;
	struct lldp_interface *lifp = NULL;
	ifp = vty->index;
	if (ifp)
		lifp = ifp->info;
	if (lifp == NULL)
		return CMD_WARNING;
	if (argc == 0) {
		if (lifp->mode & LLDP_READ_MODE)
			return CMD_SUCCESS;
		lifp->mode |= LLDP_READ_MODE; /* 使能状态 */
	} else {
		lifp->mode |= LLDP_READ_MODE; /* 使能状态 */
#ifdef LLDP_PROTOCOL_DEBUG
		if (argv[1]) {
			if (memcmp(argv[1], "cdp", 2) == 0)
				lifp->protocol |= LLDP_CDP_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "edp", 2) == 0)
				lifp->protocol |= LLDP_EDP_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "fdp", 2) == 0)
				lifp->protocol |= LLDP_FDP_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "sonmp", 2) == 0)
				lifp->protocol |= LLDP_SONMP_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "lldp-med", 2) == 0)
				lifp->protocol |= LLDP_MED_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "custom", 2) == 0)
				lifp->protocol |= LLDP_CUSTOM_TYPE; /* 兼容协议 */
		}
#endif
		//lifp->frame = LLDP_FRAME_TYPE;/* LLDP 帧封装格式 */
	}
	return lldp_interface_receive_enable(ifp);
}
ALIAS (lldpd_receive,
		lldpd_receive_val_cmd,
		"lldp receive"LLDP_PROTOCOL,
		LLDP_STR
		"lldpd receive enable\n"
		LLDP_PROTOCOL_HELP)

DEFUN (no_lldpd_receive,
		no_lldpd_receive_cmd,
	    "no lldp receive",
		NO_STR
		LLDP_STR
		"lldpd receive enable\n")
{
	struct interface *ifp = NULL;
	struct lldp_interface *lifp = NULL;
	ifp = vty->index;
	if (ifp)
		lifp = ifp->info;
	if (lifp == NULL)
		return CMD_WARNING;
	if (argc == 0) {
		if ((lifp->mode & LLDP_READ_MODE) == 0)
			return CMD_SUCCESS;
		lifp->mode &= ~(LLDP_READ_MODE); /* 去使能状态 */
	} else {
		lifp->mode &= ~(LLDP_READ_MODE); /* 去使能状态 */
#ifdef LLDP_PROTOCOL_DEBUG
		if (argv[1]) {
			if (memcmp(argv[1], "cdp", 2) == 0)
				lifp->protocol &= ~LLDP_CDP_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "edp", 2) == 0)
				lifp->protocol &= ~LLDP_EDP_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "fdp", 2) == 0)
				lifp->protocol &= ~LLDP_FDP_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "sonmp", 2) == 0)
				lifp->protocol &= ~LLDP_SONMP_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "lldp-med", 2) == 0)
				lifp->protocol &= ~LLDP_MED_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "custom", 2) == 0)
				lifp->protocol &= ~LLDP_CUSTOM_TYPE; /* 兼容协议 */
		}
#endif
	}
	return lldp_interface_receive_enable(ifp);
}
ALIAS (no_lldpd_receive,
		no_lldpd_receive_val_cmd,
	    "no lldp receive"LLDP_PROTOCOL,
	    NO_STR
		LLDP_STR
		"lldpd receive enable\n"
		LLDP_PROTOCOL_HELP)


DEFUN (lldpd_transmit,
		lldpd_transmit_cmd,
	    "lldp transmit",
		LLDP_STR
		"lldpd transmit enable\n")
{
	struct interface *ifp = NULL;
	struct lldp_interface *lifp = NULL;
	ifp = vty->index;
	if (ifp)
		lifp = ifp->info;
	if (lifp == NULL)
		return CMD_WARNING;
	if (argc == 0) {
		if ((lifp->mode & LLDP_WRITE_MODE))
			return CMD_SUCCESS;
		lifp->mode |= LLDP_WRITE_MODE; /* 使能状态 */
	} else {
		lifp->mode |= LLDP_WRITE_MODE; /* 使能状态 */
#ifdef LLDP_PROTOCOL_DEBUG
		if (argv[1]) {
			if (memcmp(argv[1], "cdp", 2) == 0)
				lifp->protocol |= LLDP_CDP_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "edp", 2) == 0)
				lifp->protocol |= LLDP_EDP_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "fdp", 2) == 0)
				lifp->protocol |= LLDP_FDP_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "sonmp", 2) == 0)
				lifp->protocol |= LLDP_SONMP_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "lldp-med", 2) == 0)
				lifp->protocol |= LLDP_MED_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "custom", 2) == 0)
				lifp->protocol |= LLDP_CUSTOM_TYPE; /* 兼容协议 */
		}
#endif
	}
	return lldp_interface_transmit_enable(ifp);
}
ALIAS (lldpd_transmit,
		lldpd_transmit_val_cmd,
	   "lldp transmit"LLDP_PROTOCOL,
		LLDP_STR
		"lldpd transmit enable\n"
		LLDP_PROTOCOL_HELP)

DEFUN (no_lldpd_transmit,
		no_lldpd_transmit_cmd,
	    "no lldp transmit",
		NO_STR
		LLDP_STR
		"lldpd transmit enable\n")
{
	struct interface *ifp = NULL;
	struct lldp_interface *lifp = NULL;
	ifp = vty->index;
	if (ifp)
		lifp = ifp->info;
	if (lifp == NULL)
		return CMD_WARNING;
	if (argc == 0) {
		if ((lifp->mode & LLDP_WRITE_MODE) == 0)
			return CMD_SUCCESS;
		lifp->mode &= ~(LLDP_WRITE_MODE); /* 去使能状态 */
	} else {
		lifp->mode &= ~(LLDP_WRITE_MODE); /* 去使能状态 */
#ifdef LLDP_PROTOCOL_DEBUG
		if (argv[1]) {
			if (memcmp(argv[1], "cdp", 2) == 0)
				lifp->protocol &= ~LLDP_CDP_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "edp", 2) == 0)
				lifp->protocol &= ~LLDP_EDP_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "fdp", 2) == 0)
				lifp->protocol &= ~LLDP_FDP_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "sonmp", 2) == 0)
				lifp->protocol &= ~LLDP_SONMP_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "lldp-med", 2) == 0)
				lifp->protocol &= ~LLDP_MED_TYPE; /* 兼容协议 */
			if (memcmp(argv[1], "custom", 2) == 0)
				lifp->protocol &= ~LLDP_CUSTOM_TYPE; /* 兼容协议 */
		}
#endif
	}
	return lldp_interface_transmit_enable(ifp);
}
ALIAS (no_lldpd_transmit,
		no_lldpd_transmitval_cmd,
	    "no lldp transmit"LLDP_PROTOCOL,
	    NO_STR
		LLDP_STR
		"lldpd transmit enable\n"
		LLDP_PROTOCOL_HELP)


DEFUN (lldpd_time_interval,
		lldpd_time_interval_cmd,
	    "lldp (hello-interval|hold-time|reinit) <1-65536>",
		LLDP_STR
		"lldpd hello interval\n"
		"lldpd DB hold time\n"
		"lldpd DB reinit\n"
		"time value (sec)\n")
{
	int value;
	struct interface *ifp = NULL;
	struct lldp_interface *lifp = NULL;
	ifp = vty->index;
	if (ifp)
		lifp = ifp->info;
	if (lifp == NULL)
		return CMD_WARNING;
	if (argv[0] == NULL || argv[1] == NULL) {
		vty_out(vty, "Invalid input argvment %s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	value = atoi(argv[1]);
	if (value < 1 || value > 600) {
		vty_out(vty, "Invalid input sec value ,you may input 1 - 65536%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (memcmp(argv[0], "hello-interval", 2) == 0)
		lifp->lldp_timer = value;
	else if (memcmp(argv[0], "hold-time", 2) == 0)
		lifp->lldp_holdtime = value;
	else if (memcmp(argv[0], "reinit", 2) == 0)
		lifp->lldp_reinit = value;
	else {
		vty_out(vty, "Invalid input argvment %s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	return lldp_interface_transmit_enable(ifp);
}
DEFUN (no_lldpd_time_interval,
		no_lldpd_time_interval_cmd,
	    "no lldp (hello-interval|hold-time|reinit)",
		NO_STR
		LLDP_STR
		"lldpd hello interval\n"
		"lldpd DB hold time\n"
		"lldpd DB reinit\n")
{
	struct interface *ifp = NULL;
	struct lldp_interface *lifp = NULL;
	ifp = vty->index;
	if (ifp)
		lifp = ifp->info;
	if (lifp == NULL)
		return CMD_WARNING;
	if (argv[0] == NULL) {
		vty_out(vty, "Invalid input argvment %s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (memcmp(argv[0], "hello-interval", 2) == 0)
		lifp->lldp_timer = LLDP_HELLO_TIME_DEFAULT;
	else if (memcmp(argv[0], "hold-time", 2) == 0)
		lifp->lldp_holdtime = LLDP_HOLD_TIME_DEFAULT;
	else if (memcmp(argv[0], "reinit", 2) == 0)
		lifp->lldp_reinit = LLDP_REINIT_TIME_DEFAULT;
	else {
		vty_out(vty, "Invalid input argvment %s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	return lldp_interface_transmit_enable(ifp);
}


static int lldp_interface_config_write(struct vty *vty)
{
	struct listnode *node;
	struct interface *ifp;
	struct lldp_interface *lifp;

	for (ALL_LIST_ELEMENTS_RO(iflist, node, ifp)) {
		vty_out(vty, "interface %s%s", ifp->name, VTY_NEWLINE);

		if (ifp->desc)
			vty_out(vty, " description %s%s", ifp->desc, VTY_NEWLINE);
		lifp = ifp->info;
		if (lifp == NULL)
			continue;
		if (lifp->mode != LLDP_DISABLE) {
#ifdef LLDP_PROTOCOL_DEBUG
			if (lifp->mode == LLDP_DISABLE)
				vty_out(vty, " lldp disable %s", VTY_NEWLINE);
			if (lifp->mode & LLDP_READ_MODE)
				vty_out(vty, " lldp receive %s", VTY_NEWLINE);
			if (lifp->mode & LLDP_WRITE_MODE)
				vty_out(vty, " lldp transmit %s", VTY_NEWLINE);
			if (lifp->mode ！= LLDP_DISABLE)
				vty_out(vty, " lldp med %s", VTY_NEWLINE);

			if (lifp->protocol & LLDP_CDP_TYPE) /* Cisco Discovery Protocol */
				sprintf(proto, "%s", "cdp");
			break;
		case LLDP_EDP_TYPE: /* Extreme Discovery Protocol */
			sprintf(proto, "%s", "edp");
			break;
		case LLDP_FDP_TYPE: /* Foundry Discovery Protocol */
			sprintf(proto, "%s", "fdp");
			break;
		case LLDP_DOT1_TYPE: /* Dot1 extension (VLAN stuff) */
			sprintf(proto, "%s", "dot1");
			break;
		case LLDP_DOT3_TYPE: /* Dot3 extension (PHY stuff) */
			sprintf(proto, "%s", "dot3");
			break;
		case LLDP_SONMP_TYPE: /*  */
			sprintf(proto, "%s", "sonmp");
			break;
		case LLDP_MED_TYPE: /* LLDP-MED extension */
			sprintf(proto, "%s", "med");
			break;
		case LLDP_CUSTOM_TYPE: /* Custom TLV support */
			sprintf(proto, "%s", "custom");
			break;
		}
#else
			vty_out(vty, " lldp enable %s", VTY_NEWLINE);
			if (lifp->mode & LLDP_READ_MODE)
				vty_out(vty, " lldp receive %s", VTY_NEWLINE);
			if (lifp->mode & LLDP_WRITE_MODE)
				vty_out(vty, " lldp transmit %s", VTY_NEWLINE);
			if (lifp->mode & LLDP_ENABLE)
				vty_out(vty, " lldp med %s", VTY_NEWLINE);
#endif

		if (lifp->lldp_timer != LLDP_HELLO_TIME_DEFAULT)
			vty_out(vty, " lldp hello-interval %d %s", lifp->lldp_timer, VTY_NEWLINE);
		if (lifp->lldp_timer != LLDP_HOLD_TIME_DEFAULT)
			vty_out(vty, " lldp hold-time %d %s", lifp->lldp_holdtime, VTY_NEWLINE);
		if (lifp->lldp_timer != LLDP_REINIT_TIME_DEFAULT)
			vty_out(vty, " lldp reinit %d %s", lifp->lldp_reinit, VTY_NEWLINE);

		//vty_out (vty, "!%s", VTY_NEWLINE);
	}
	vty_out(vty, "!%s", VTY_NEWLINE);
}
return CMD_SUCCESS;
}

static struct cmd_node interface_node = {
	INTERFACE_NODE,
	"%s(config-if)# ",
	1,
};


void lldp_interface_vty_init(void)
{
	install_node(&interface_node, lldp_interface_config_write);

	install_default(INTERFACE_NODE);

	install_element(VIEW_NODE, &show_lldp_interface_cmd);
	install_element(ENABLE_NODE, &show_lldp_interface_cmd);

	install_element(CONFIG_NODE, &interface_cmd);
	install_element(CONFIG_NODE, &no_interface_cmd);
	install_element(INTERFACE_NODE, &interface_desc_cmd);
	install_element(INTERFACE_NODE, &no_interface_desc_cmd);

	install_element(INTERFACE_NODE, &lldpd_enable_cmd);
	install_element(INTERFACE_NODE, &no_lldpd_enable_cmd);

#ifdef LLDP_PROTOCOL_DEBUG
	install_element(INTERFACE_NODE, &lldpd_transmit_val_cmd);
	install_element(INTERFACE_NODE, &no_lldpd_transmit_val_cmd);
	install_element(INTERFACE_NODE, &lldpd_receive_val_cmd);
	install_element(INTERFACE_NODE, &no_lldpd_receive_val_cmd);
#endif

	install_element(INTERFACE_NODE, &lldpd_transmit_cmd);
	install_element(INTERFACE_NODE, &no_lldpd_transmit_cmd);
	install_element(INTERFACE_NODE, &lldpd_receive_cmd);
	install_element(INTERFACE_NODE, &no_lldpd_receive_cmd);


	install_element(INTERFACE_NODE, &lldpd_time_interval_cmd);
	install_element(INTERFACE_NODE, &no_lldpd_time_interval_cmd);
}


/* EOF */
