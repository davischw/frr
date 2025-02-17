/*
 * lldp_interface.c
 *
 *  Created on: Oct 24, 2016
 *      Author: zhurish
 */

#include <zebra.h>

#include "command.h"
#include "freebsd-queue.h"
#include "vty.h"

/* TODO: re-add headers as needed, otherwise remove
#include "prefix.h"
#include "table.h"
#include "stream.h"
#include "memory.h"
#include "routemap.h"
#include "zclient.h"
#include "log.h"
*/

#include "lldpd.h"
#include "lldp_memory.h"
#include "lldp_interface.h"

/* TODO: re-add headers as needed, otherwise remove
#include "lldp_db.h"
#include "lldp_packet.h"
#include "lldp_socket.h"
*/


/* LLDP interface information list */
TAILQ_HEAD(lldp_interface_list, lldp_interface) lldp_iface_list;


unsigned char lldp_dst_mac[LLDP_DST_MAC_MAX][ETH_ALEN] = {
	{ 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E },
	{ 0x01, 0x80, 0xC2, 0x00, 0x00, 0x03 },
	{ 0x01, 0x80, 0xC2, 0x00, 0x00, 0x00 },
	{ 0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC }, /* Cisco CDP */
};

/*
static void hwaddr2mac(uint8_t *src_hwaddr, unsigned char *dst_mac)
{
	if (src_hwaddr && dst_mac) {
		memcpy(src_hwaddr, dst_mac, ETH_ALEN);
	}
}
*/


/* Allocate LLDP interface information */
static struct lldp_interface *lldp_interface_new(void)
{
	struct lldp_interface *lifp;

	lifp = XCALLOC(MTYPE_LLDP_IF_INFO, sizeof(struct lldp_interface));
	if (lifp) {
		memset(lifp, 0, sizeof(struct lldp_interface));

		lifp->mode = 0; //LLDP_WRITE_MODE;/* 使能状态 */

#ifdef LLDP_PROTOCOL_DEBUG
		lifp->protocol = LLDP_CDP_TYPE; /* 兼容协议 */
#endif
		lifp->states = 0;	       /* 接口状态 */
		lifp->frame = LLDP_FRAME_TYPE; /* LLDP 帧封装格式 */
		lifp->Changed = 0;	       /* 本地信息发生变动 */
		lifp->capabilities = 1;	       /*  */

		lifp->lldp_timer = LLDP_HELLO_TIME_DEFAULT;	 /* 定时时间 */
		lifp->lldp_holdtime = LLDP_HOLD_TIME_DEFAULT;	 /* 生存时间 */
		lifp->lldp_reinit = LLDP_REINIT_TIME_DEFAULT;	 /* 重新初始化时间 */
		lifp->lldp_fast_count = LLDP_FAST_COUNT_DEFAULT; /* 快速发送计数 */
		//lifp->lldp_tlv_select	= 0xffffff;//TLV选择
		//lifp->lldp_check_interval = LLDP_CHECK_TIME_DEFAULT;//本地检测周期，检测本地信息是否发生变化

		/*
		 * TODO: Do these things during allocation or later during
		 * interface enable ?
		 */
		//lifp->lldpd = lldpd_config;
		memcpy(lifp->dst_mac, lldp_dst_mac[LLDP_DST_MAC1], ETH_ALEN);
		//lifp->ibuf = stream_new (LLDP_PACKET_MAX_SIZE);
		//lifp->obuf = stream_new (LLDP_PACKET_MAX_SIZE);

		lifp->ifp = NULL;
	}

	return lifp;
}


/* Delete LLDP interface information. */
static void lldp_interface_delete(struct lldp_interface *lifp)
{
	if (lifp) {
		/* TODO: free io streams, etc. */

		XFREE(MTYPE_LLDP_IF_INFO, lifp);
	}
}


/* Hook to add interface */
int lldp_interface_add_hook(struct interface *ifp)
{
	struct lldp_interface *lifp;

	if (ifp->info)
		return CMD_SUCCESS;

	lifp = lldp_interface_new();
	if (lifp) {
		ifp->info = lifp;

		//lifp->lldpd = lldpd_config;
		//memcpy(lifp->dst_mac, lldp_dst_mac[LLDP_DST_MAC1], ETH_ALEN);

		//lifp->ibuf = stream_new (LLDP_PACKET_MAX_SIZE);
		//lifp->obuf = stream_new (LLDP_PACKET_MAX_SIZE);
		//if(memcmp(ifp->name, "eno16777736",strlen("eno16777736"))==0)
		//lldp_interface_enable(ifp, LLDP_WRITE_MODE|LLDP_READ_MODE, LLDP_CDP_TYPE);

		lifp->ifp = ifp;

		TAILQ_INSERT_TAIL(&lldp_iface_list, lifp, entry);

		return CMD_SUCCESS;
	}

	return CMD_WARNING;
}


/* Hook to remove interface. */
int lldp_interface_remove_hook(struct interface *ifp)
{
	struct lldp_interface *lifp = NULL;

	if (ifp->info) {
		lifp = ifp->info;

		TAILQ_REMOVE(&lldp_iface_list, lifp, entry);
		lldp_interface_delete(lifp);

		ifp->info = NULL;
	}

	return CMD_SUCCESS;
}


/* Initialize LLDP interfaces */
void lldp_interface_init(void)
{
	/* TODO: check if needed/can be replaced by zebra hooks
	if_init();
	if_add_hook(IF_NEW_HOOK, lldp_interface_new_hook);
	if_add_hook(IF_DELETE_HOOK, lldp_interface_delete_hook);
	*/

	/* TODO: initialize interface list (iflist ?) */
	TAILQ_INIT(&lldp_iface_list);
}


/* Terminate LLDP interfaces */
void lldp_interface_terminate(void)
{
	struct lldp_interface *lifp = NULL;
	struct lldp_interface *lifp_tmp = NULL;

	TAILQ_FOREACH_SAFE(lifp, &lldp_iface_list, entry, lifp_tmp) {
		/* TODO: disable interface ? */

		TAILQ_REMOVE(&lldp_iface_list, lifp, entry);
		lldp_interface_delete(lifp);
	}
}


static void show_lldp_interface(struct vty *vty, struct lldp_interface *lifp)
{
	char str[64];

	vty_out(vty, "interface %s\n", lifp->ifp->name);

	if (lifp->ifp->desc)
		vty_out(vty, " description %s\n", lifp->ifp->desc);

	if (lifp->mode == LLDP_DISABLE) {
		vty_out(vty, "  lldp disable\n");
	} else {
		memset(str, 0, sizeof(str));

		if (lifp->mode & LLDP_READ_MODE)
			strcat(str, "rx");

		if (lifp->mode & LLDP_WRITE_MODE)
			strcat(str, "tx");

		vty_out(vty, "  lldp enable %s\n", str);
	}

	vty_out(vty, "  lldp own mac : %02x-%02x-%02x-%02x-%02x-%02x\n", lifp->own_mac[0],
		lifp->own_mac[1], lifp->own_mac[2], lifp->own_mac[3], lifp->own_mac[4],
		lifp->own_mac[5]);

	vty_out(vty, "  lldp frame : %s%d\n", (lifp->frame == SNAP_FRAME_TYPE) ? "snap" : "lldp",
		lifp->states);

	vty_out(vty, "  holdtime: %d reinit: %d fast-count: %d\n", lifp->lldp_holdtime,
		lifp->lldp_reinit, lifp->lldp_holdtime);

	vty_out(vty, "  capabilities : 0x%x\n", lifp->capabilities);
}


int show_lldp_interface_all(struct vty *vty)
{
	struct lldp_interface *lifp = NULL;

	TAILQ_FOREACH(lifp, &lldp_iface_list, entry) {
		show_lldp_interface(vty, lifp);
	}

	return CMD_SUCCESS;
}


/* EOF */
