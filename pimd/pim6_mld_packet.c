/*
 * MLD packet handling implementation.
 * Copyright (C) 2024 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <zebra.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "lib/checksum.h"
#include "lib/linklist.h"
#include "lib/network.h"
#include "pimd/pim6_mld.h"
#include "pimd/pim6_mld_packet.h"
#include "pimd/pim6_mld_protocol.h"
#include "pimd/pim_iface.h"

/**
 * Minimum expected MTU to generate the multicast packets is the IPv6
 * recommendation of 1280 bytes (otherwise the underlying layer must
 * provide fragmentation/assembly).
 *
 * See "RFC 2460 Section 5. Packet Size Issues".
 */
static const size_t multicast_minimum_mtu = 1280;

static const struct in6_addr in6_zero;

struct mld_group_source {
	SLIST_ENTRY(mld_group_source) entry;

	struct in6_addr source;
};
SLIST_HEAD(mld_group_source_list, mld_group_source);

struct mld_group {
	SLIST_ENTRY(mld_group) entry;

	bool star_source;
	size_t source_count;
	struct in6_addr group;
	struct mld_group_source_list source_list;
};
SLIST_HEAD(mld_group_list, mld_group);

static struct mld_group_source *
mld_group_source_get(struct mld_group *group, const struct in6_addr *source)
{
	struct mld_group_source *group_source;

	if (pim_addr_cmp(in6_zero, *source) == 0) {
		group->star_source = true;
		return NULL;
	}

	SLIST_FOREACH (group_source, &group->source_list, entry)
		if (pim_addr_cmp(*source, group_source->source) == 0)
			return group_source;

	group->source_count++;

	group_source = XCALLOC(MTYPE_TMP, sizeof(struct mld_group_source));
	group_source->source = *source;
	SLIST_INSERT_HEAD(&group->source_list, group_source, entry);

	return group_source;
}

static struct mld_group *mld_group_get(struct mld_group_list *groups,
				       const struct in6_addr *group)
{
	struct mld_group *mld_group;

	SLIST_FOREACH (mld_group, groups, entry)
		if (pim_addr_cmp(*group, mld_group->group) == 0)
			return mld_group;

	mld_group = XCALLOC(MTYPE_TMP, sizeof(struct mld_group));
	mld_group->group = *group;
	SLIST_INSERT_HEAD(groups, mld_group, entry);

	return mld_group;
}

static void mld_group_list_get(const struct in6_addr *source,
			       const struct in6_addr *group,
			       const struct list *gm_list,
			       struct mld_group_list *group_list)
{
	const struct gm_join *gm_join;
	const struct listnode *node;
	struct mld_group *mld_group;

	if (gm_list == NULL || list_isempty(gm_list))
		return;

	for (ALL_LIST_ELEMENTS_RO(gm_list, node, gm_join)) {
		if (group && pim_addr_cmp(*group, gm_join->group_addr))
			continue;
		if (source && pim_addr_cmp(*source, gm_join->source_addr))
			continue;

		mld_group = mld_group_get(group_list, &gm_join->group_addr);
		mld_group_source_get(mld_group, &gm_join->source_addr);
	}
}


static void mld_group_list_free(struct mld_group_list *group_list)
{
	struct mld_group *group;
	struct mld_group_source *group_source;

	while (!SLIST_EMPTY(group_list)) {
		group = SLIST_FIRST(group_list);

		while (!SLIST_EMPTY(&group->source_list)) {
			group_source = SLIST_FIRST(&group->source_list);
			SLIST_REMOVE(&group->source_list, group_source,
				     mld_group_source, entry);
			XFREE(MTYPE_TMP, group_source);
		}

		SLIST_REMOVE(group_list, group, mld_group, entry);
		XFREE(MTYPE_TMP, group);
	}
}

struct mld_packet_params {
	/** Selected source address */
	const struct in6_addr *source;
	/** Selected group address */
	const struct in6_addr *group;
	/** Selected packet source address */
	const struct in6_addr *packet_source;
	/** Packet list to append packets */
	struct mld_packet_list *list;
	/** Maximum packet size */
	size_t size;
	/** MLD version */
	enum gm_version version;
	/** Action type: `true` join, `false` leave */
	bool join;
	/** List of group/source to act on. */
	struct mld_group_list groups;
};

static struct mld_packet *mld_new_packet(struct mld_packet_params *params)
{
	struct mld_packet *packet;
	size_t packet_size = sizeof(struct mld_packet) +
			     sizeof(struct ipv6_ph) + params->size;

	packet = XCALLOC(MTYPE_TMP, packet_size);
	SLIST_INSERT_HEAD(params->list, packet, entry);
	packet->max_size = params->size;

	packet->ip6 = (struct ipv6_ph *)packet->data;
	packet->icmp6 =
		(struct icmp6_plain_hdr *)&packet->data[sizeof(struct ipv6_ph)];
	packet->size = sizeof(struct icmp6_plain_hdr);
	packet->ip6->src = *params->packet_source;
	packet->ip6->next_hdr = PIM_IPV6_ENCAP_MLD;
	inet_pton(AF_INET6, "FF02::1", &packet->ip6->dst);

	switch (params->version) {
	case GM_MLDV1:
		if (params->join)
			packet->icmp6->icmp6_type = ICMP6_MLD_V1_REPORT;
		else
			packet->icmp6->icmp6_type = ICMP6_MLD_V1_DONE;

		packet->mldv1 = (struct mld_v1_pkt *)(packet->icmp6 + 1);
		packet->size += sizeof(struct mld_v1_pkt);
		break;
	case GM_MLDV2:
		packet->icmp6->icmp6_type = ICMP6_MLD_V2_REPORT;
		packet->mldv2 = (struct mld_v2_report_hdr *)(packet->icmp6 + 1);
		packet->size += sizeof(struct mld_v2_report_hdr);
		break;

	case GM_NONE:
	default:
		break;
	}

	return packet;
}

static void mld_packet_finish(struct mld_packet *packet)
{
	packet->ip6->ulpl = htonl((uint32_t)packet->size);
	packet->icmp6->icmp6_cksum =
		in_cksum_with_ph6(packet->ip6, packet->icmp6, packet->size);
}

static inline bool mldv2_packet_group_fit(const struct mld_packet *packet)
{
	size_t total_size;

	total_size = sizeof(struct mld_v2_rec_hdr) + sizeof(struct in6_addr);
	if ((packet->size + total_size) > packet->max_size)
		return false;

	return true;
}

static const struct mld_group_source *
mldv2_packet_add_record(struct mld_packet *packet, bool join,
			const struct mld_group *group,
			const struct mld_group_source *source_head)
{
	const struct mld_group_source *source = NULL;
	struct mld_v2_rec_hdr *record;
	const uint16_t records_number = ntohs(packet->mldv2->n_records);
	size_t source_index;

	packet->size += sizeof(struct mld_v2_rec_hdr);
	if (packet->cur_record)
		record = (struct mld_v2_rec_hdr *)packet->cur_record;
	else
		record = (struct mld_v2_rec_hdr *)(packet->mldv2 + 1);

	packet->mldv2->n_records = htons(records_number + 1);
	record->grp = group->group;
	if (join) {
		if (group->star_source || group->source_count == 0)
			record->type = MLD_RECTYPE_CHANGE_TO_EXCLUDE;
		else
			record->type = MLD_RECTYPE_ALLOW_NEW_SOURCES;
	} else {
		if (group->star_source || group->source_count == 0)
			record->type = MLD_RECTYPE_CHANGE_TO_INCLUDE;
		else
			record->type = MLD_RECTYPE_BLOCK_OLD_SOURCES;
	}

	if (source_head == NULL)
		source_head = SLIST_FIRST(&group->source_list);

	source_index = 0;
	for (source = source_head; source; source = SLIST_NEXT(source, entry)) {
		record->srcs[source_index] = source->source;
		source_index++;
		record->n_src = ntohs((uint16_t)source_index);
		packet->size += sizeof(struct in6_addr);
		if (packet->size >= packet->max_size)
			break;
	}

	packet->cur_record = (uint8_t *)&record->srcs[source_index];

	if (record->type == MLD_RECTYPE_IS_EXCLUDE ||
	    record->type == MLD_RECTYPE_CHANGE_TO_EXCLUDE)
		return NULL;

	return source;
}

static void mldv2_generate_packets(struct mld_packet_params *params)
{
	const struct mld_group_source *last_group_source = NULL;
	const struct mld_group *group;
	struct mld_packet *packet;

	packet = mld_new_packet(params);

	SLIST_FOREACH (group, &params->groups, entry) {
		do {
			if (mldv2_packet_group_fit(packet)) {
				mld_packet_finish(packet);
				packet = mld_new_packet(params);
			}

			last_group_source = mldv2_packet_add_record(
				packet, params->join, group, last_group_source);
		} while (last_group_source);
	}

	mld_packet_finish(packet);
}

static void mldv1_generate_packets(struct mld_packet_params *params)
{
	struct mld_group *group;
	struct mld_packet *packet;
	struct mld_v1_pkt *mld;

	SLIST_FOREACH (group, &params->groups, entry) {
		packet = mld_new_packet(params);
		mld = packet->mldv1;
		mld->grp = group->group;
		mld_packet_finish(packet);
	}
}

static inline void mld_generate_packets(struct mld_packet_params *params)
{
	switch (params->version) {
	case GM_MLDV1:
		params->list =
			XCALLOC(MTYPE_TMP, sizeof(struct mld_packet_list));
		mldv1_generate_packets(params);
		break;
	case GM_MLDV2:
		params->list =
			XCALLOC(MTYPE_TMP, sizeof(struct mld_packet_list));
		mldv2_generate_packets(params);
		break;

	default:
	case GM_NONE:
		break;
	}

	if (params->list && SLIST_EMPTY(params->list))
		XFREE(MTYPE_TMP, params->list);
}

struct mld_packet_list *
mld_generate_packet_list(const struct interface *interface, bool join,
			 const struct in6_addr *source,
			 const struct in6_addr *group)
{
	const struct pim_interface *pim_interface = interface->info;
	struct mld_packet_params packet_params;

	memset(&packet_params, 0, sizeof(packet_params));
	packet_params.source = source;
	packet_params.group = group;
	packet_params.join = join;
	packet_params.version = (enum gm_version)pim_interface->mld_version;
	packet_params.packet_source = &pim_interface->ll_lowest;
	if (interface->mtu < multicast_minimum_mtu) {
		zlog_warn("Interface %s MTU is too low (%d bytes)",
			  interface->name, interface->mtu);
		packet_params.size = multicast_minimum_mtu;
	} else
		packet_params.size = interface->mtu;

	mld_group_list_get(source, group, pim_interface->gm_join_list,
			   &packet_params.groups);
	mld_generate_packets(&packet_params);
	mld_group_list_free(&packet_params.groups);

	return packet_params.list;
}

void mld_free_packet_list(struct mld_packet_list *packet_list)
{
	struct mld_packet *packet;

	while (!SLIST_EMPTY(packet_list)) {
		packet = SLIST_FIRST(packet_list);
		SLIST_REMOVE(packet_list, packet, mld_packet, entry);
		XFREE(MTYPE_TMP, packet);
	}

	XFREE(MTYPE_TMP, packet_list);
}
