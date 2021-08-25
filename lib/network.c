/*
 * Network library.
 * Copyright (C) 1997 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include "log.h"
#include "command.h"
#include "memory.h"
#include "monotime.h"
#include "network.h"
#include "lib_errors.h"
#include "checksum.h"
#include "openbsd-queue.h"
#include "thread.h"

/* Read nbytes from fd and store into ptr. */
int readn(int fd, uint8_t *ptr, int nbytes)
{
	int nleft;
	int nread;

	nleft = nbytes;

	while (nleft > 0) {
		nread = read(fd, ptr, nleft);

		if (nread < 0)
			return (nread);
		else if (nread == 0)
			break;

		nleft -= nread;
		ptr += nread;
	}

	return nbytes - nleft;
}

/* Write nbytes from ptr to fd. */
int writen(int fd, const uint8_t *ptr, int nbytes)
{
	int nleft;
	int nwritten;

	nleft = nbytes;

	while (nleft > 0) {
		nwritten = write(fd, ptr, nleft);

		if (nwritten < 0) {
			if (!ERRNO_IO_RETRY(errno))
				return nwritten;
		}
		if (nwritten == 0)
			return (nwritten);

		nleft -= nwritten;
		ptr += nwritten;
	}
	return nbytes - nleft;
}

int set_nonblocking(int fd)
{
	int flags;

	/* According to the Single UNIX Spec, the return value for F_GETFL
	   should
	   never be negative. */
	if ((flags = fcntl(fd, F_GETFL)) < 0) {
		flog_err(EC_LIB_SYSTEM_CALL,
			 "fcntl(F_GETFL) failed for fd %d: %s", fd,
			 safe_strerror(errno));
		return -1;
	}
	if (fcntl(fd, F_SETFL, (flags | O_NONBLOCK)) < 0) {
		flog_err(EC_LIB_SYSTEM_CALL,
			 "fcntl failed setting fd %d non-blocking: %s", fd,
			 safe_strerror(errno));
		return -1;
	}
	return 0;
}

int set_cloexec(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFD, 0);
	if (flags == -1)
		return -1;

	flags |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, flags) == -1)
		return -1;
	return 0;
}

float htonf(float host)
{
	uint32_t lu1, lu2;
	float convert;

	memcpy(&lu1, &host, sizeof(uint32_t));
	lu2 = htonl(lu1);
	memcpy(&convert, &lu2, sizeof(uint32_t));
	return convert;
}

float ntohf(float net)
{
	return htonf(net);
}

/*
 * IPv4 fragmentation handling.
 */

DEFINE_MTYPE_STATIC(LIB, PACKET_FRAGMENT, "IP packet fragment");
DEFINE_MTYPE_STATIC(LIB, PACKET_DATA, "IP packet assembled data");

/** A packet fragment holder data structure. */
struct packet_fragment {
	/** List pointer. */
	SLIST_ENTRY(packet_fragment) entry;
	/** Data offset. */
	uint16_t offset;
	/** Fragment size. */
	uint16_t size;
	/** Fragment data (allocated dinamically during *alloc). */
	uint8_t data[];
};

/** Packet fragment list definition. */
SLIST_HEAD(packet_fragment_list, packet_fragment);

/**
 * IP packet identification.
 *
 * In order for a fragment to belong to this packet it must match
 * the following criteria: it must have the same source address,
 * destination address, identification and protocol.
 *
 * RFC 791 Section 3.2. Discussion.
 */
struct ipv4_identification {
	/** Identification field. */
	uint16_t id;
	/** Protocol. */
	uint16_t protocol;
	/** Source address. */
	uint32_t source;
	/** Destination address. */
	uint32_t destination;
};

enum ip_packet_flag {
	/** Data structure is in use. */
	IP_PACKET_IN_USE = (1 << 0),
	/** Currently being used to assemble IPv4 packet. */
	IP_PACKET_IPV4 = (1 << 1),
	/** Packet is complete. */
	IP_PACKET_COMPLETE = (1 << 2),
	/**
	 * Ignore this packet:
	 * This packet has been flagged to be ignored for one on the reasons:
	 *  1. Its too fragmented so only account it once for statistics.
	 *  2. Its a huge packet and should not be accounted more than once.
	 *  3. Its a repeated packet.
	 *
	 *  The packet will be ignored until it ceases its activity and gets
	 *  cleaned up by the periodic timer.
	 */
	IP_PACKET_IGNORE = (1 << 3),
};

/**
 * Data structure that symbolizes the entire packet.
 *
 * It holds all fragments and can be used to build the whole packet.
 */
struct ip_packet {
	/** Packet identification. */
	struct ipv4_identification id;
	/** Amount of fragments. */
	uint16_t total_fragments;
	/** Data structure flags. \see ip_packet_flag. */
	uint16_t flags;
	/** Current amount of fragmented data. */
	uint32_t current_size;
	/** Total packet size. */
	uint32_t total_size;
	/** Final header size. */
	uint32_t header_size;
	/** Fragments list. */
	struct packet_fragment_list fragments;
	/** Last access. */
	time_t last_usage;
	/** Packet complete data. */
	uint8_t *data;
};

/** Encapsulation ToS value. */
#define IPV4_ENCAP_TOS 0xC0
/** Encapsulation magic value. */
#define IP_ENCAP_MAGIC_VALUE 0x676F6C64


static struct ip_packet packet_list[PACKET_ASSEMBLY_IN_PROGRESS_MAX];
static struct thread_master *packet_thread;
static struct thread *packet_cleanup_timer;
static struct thread *packet_cleanup_event;
struct ip_packet_statistics ip_packet_stats;

/**
 * Statistic counters for IP assembly/fragmentation.
 */
struct ip_encap_packet_statistics {
	/** Invalid IP header version. */
	uint64_t invalid_version;
	/** Invalid header length: less than 5 octets (or 20 bytes). */
	uint64_t invalid_header_length;
	/** Invalid packet length: header says X but packet data is Y. */
	uint64_t invalid_packet_length;
	/** Invalid checksum. */
	uint64_t invalid_checksum;
	/** IP encapsulation fragment detected: no fragmentation used. */
	uint64_t fragmented;
	/** Invalid IP encapsulation version. */
	uint64_t invalid_encapsulation_version;
	/** Invalid IP encapsulation magic number. */
	uint64_t invalid_encapsulation_magic;
	/** Valid packets. */
	uint64_t valid_packets;
} ip_encap_packet_stats;

/** Free packet resources. */
static void ip_packet_reset(struct ip_packet *packet)
{
	struct packet_fragment *pf;

	/* Free resources. */
	while ((pf = SLIST_FIRST(&packet->fragments)) != NULL) {
		SLIST_REMOVE(&packet->fragments, pf, packet_fragment, entry);
		XFREE(MTYPE_PACKET_FRAGMENT, pf);
	}
	XFREE(MTYPE_PACKET_DATA, packet->data);

	/* Reset variables. */
	memset(packet, 0, sizeof(*packet));
}

/** Clean up a packet after usage. */
static int ip_packet_cleanup_event(struct thread *t)
{
	struct ip_packet *packet = THREAD_ARG(t);

	ip_packet_reset(packet);

	return 0;
}

/** Gets an existing context or an unused one. */
static struct ip_packet *ip_packet_find(const struct ipv4_header *ipv4)
{
	struct ip_packet *packet = NULL;
	int first_available = -1;
	int index;

	for (index = 0; index < PACKET_ASSEMBLY_IN_PROGRESS_MAX; index++) {
		/* Figure out the first available slot or just skip. */
		if (!(packet_list[index].flags & IP_PACKET_IN_USE)) {
			if (first_available != -1)
				continue;

			first_available = index;
			continue;
		}

		/* Skip used IPv6 packet. */
		if (!(packet_list[index].flags & IP_PACKET_IPV4))
			continue;

		/* Match identification. */
		if (ipv4->id != packet_list[index].id.id)
			continue;
		if (ipv4->protocol != packet_list[index].id.protocol)
			continue;
		if (ipv4->source != packet_list[index].id.source)
			continue;
		if (ipv4->destination != packet_list[index].id.destination)
			continue;

		packet = &packet_list[index];
		break;
	}
	if (packet)
		return packet;

	if (first_available == -1)
		return NULL;

	/* Use the new context. */
	packet = &packet_list[first_available];
	packet->flags = IP_PACKET_IN_USE | IP_PACKET_IPV4;
	packet->id.id = ipv4->id;
	packet->id.protocol = ipv4->protocol;
	packet->id.source = ipv4->source;
	packet->id.destination = ipv4->destination;

	return packet;
}

/** Allocates memory for the whole packet and assemble it. */
static void ip_packet_assemble(struct ip_packet *packet)
{
	struct packet_fragment *pf, *pfn;
	struct ipv4_header *ipv4;
	size_t offset = 0;

	/* Allocate packet data and assemble it. */
	packet->data = XMALLOC(MTYPE_PACKET_DATA,
			       packet->header_size + packet->total_size);
	SLIST_FOREACH_SAFE (pf, &packet->fragments, entry, pfn) {
		memcpy(packet->data + offset, pf->data, pf->size);
		offset += pf->size;

		SLIST_REMOVE(&packet->fragments, pf, packet_fragment, entry);
		XFREE(MTYPE_PACKET_FRAGMENT, pf);
	}

	/* Fix final IP header fields. */
	ipv4 = (struct ipv4_header *)packet->data;
	ipv4->total_length =
		(uint16_t)(packet->header_size + packet->total_size);
	ipv4->fragmentation = 0;
	ipv4->checksum = 0;
}

/** Allocates memory for fragment and register it. */
static void ip_packet_add_fragment(struct ip_packet *packet,
				   uint16_t header_length, uint16_t offset,
				   bool more_fragments, const void *data,
				   uint16_t datalen)
{
	struct packet_fragment *pf;
	struct packet_fragment *pfpos, *pfprev;
	uint16_t offset_end;

	/*
	 * Find fragment position.
	 *
	 * Handling:
	 *
	 *  * Fragment already exists:
	 *    The fragment is probably duplicated. If we want to be paranoiac
	 *    we could `memcmp` the data to detect tampering attempts.
	 *
	 *  * Fragment overlaps:
	 *    abort, it is possible someone is trying to tamper with our data.
	 *
	 *  * First fragment:
	 *    Just accept it.
	 *
	 * `pfpos` is the current iteration position and `pflast` is the last
	 * greater element before current. So if `pflast == NULL` insert at the
	 * head of the list, otherwise after `pflast`.
	 */
	pfpos = NULL;
	pfprev = NULL;
	SLIST_FOREACH (pfpos, &packet->fragments, entry) {
		/* Repeated packet: do nothing. */
		if (pfpos->offset == offset)
			return;
		/* Higher offset, we want to insert before it. */
		if (pfpos->offset > offset)
			break;

		/* Keep the current position. */
		pfprev = pfpos;
		continue;
	}

	/*
	 * Detect overlaps.
	 *
	 * Don't attempt to create a fragment it will make the size check fail
	 * (sum of all fragments) and it is probably not intended.
	 */
	if (pfprev) {
		if (pfprev->offset)
			offset_end = pfprev->offset + pfprev->size;
		else
			offset_end = pfprev->size - header_length;

		/* Previous fragment exceeds the current fragment. */
		if (offset_end > offset) {
			ip_packet_stats.fragment_overlap++;
			return;
		}
	}

	/* Detect packets that are quickly accumulating more than expected. */
	if ((packet->current_size + datalen) > IPV4_MAXIMUM_PACKET_SIZE) {
		packet->flags |= IP_PACKET_IGNORE;
		ip_packet_stats.huge_packets++;
		return;
	}

	/* Allocate resources. */
	pf = XCALLOC(MTYPE_PACKET_FRAGMENT, sizeof(*pf) + datalen);
	pf->offset = offset;
	pf->size = datalen;
	memcpy(pf->data, data, datalen);

	/* Insert item in the correct position. */
	if (pfprev)
		SLIST_INSERT_AFTER(pfprev, pf, entry);
	else
		SLIST_INSERT_HEAD(&packet->fragments, pf, entry);

	/* Update packet counters. */
	packet->total_fragments++;
	packet->current_size += datalen;
	if (!more_fragments) {
		packet->total_size = offset + datalen;
		/* Detect abnormally big packets (e.g. bigger than 65k). */
		if (packet->total_size > IPV4_MAXIMUM_PACKET_SIZE) {
			packet->flags |= IP_PACKET_IGNORE;
			ip_packet_stats.huge_packets++;
			return;
		}
	}

	packet->last_usage = monotime(NULL);

	/* Check for completion. */
	if (packet->total_size
	    && packet->total_size
		       == (packet->current_size - packet->header_size)) {
		ip_packet_assemble(packet);
		packet->flags |= IP_PACKET_COMPLETE;
		ip_packet_stats.assembled_packets++;
	}
}

enum ip_packet_assemble_result ipv4_packet_assemble(const uint8_t *data,
						    size_t datalen,
						    const uint8_t **packetp,
						    size_t *packetlen)
{
	const struct ipv4_header *ipv4 = (const struct ipv4_header *)data;
	struct ip_packet *packet;
	uint16_t fragment_length;
	uint16_t header_length;
	int checksum;

	*packetp = NULL;
	*packetlen = 0;

	/* Basic check: data size is at least the header. */
	if (datalen < sizeof(struct ipv4_header)) {
		ip_packet_stats.invalid_header_length++;
		return IPA_INVALID_HEADER_LENGTH;
	}

	/* Check version. */
	if (ipv4_version(ipv4) != 4) {
		ip_packet_stats.invalid_version++;
		return IPA_INVALID_VERSION;
	}

	/* Check header length. */
	header_length = (uint16_t)ipv4_header_length(ipv4);
	if (header_length < 20) {
		ip_packet_stats.invalid_header_length++;
		return IPA_INVALID_HEADER_LENGTH;
	}

	/* Verify checksum. */
	checksum = in_cksum(data, header_length);
	if (checksum) {
		ip_packet_stats.invalid_checksum++;
		return IPA_INVALID_CHECKSUM;
	}

	/* Check packet length. */
	fragment_length = ntohs(ipv4->total_length);
	if (datalen < fragment_length) {
		ip_packet_stats.invalid_packet_length++;
		return IPA_INVALID_LENGTH;
	}

	/* Check if this packet is fragmented. */
	if (ipv4_dont_fragment(ipv4)
	    || (!ipv4_more_fragments(ipv4)
		&& ipv4_fragment_offset(ipv4) == 0)) {
		*packetp = data;
		*packetlen = datalen;
		ip_packet_stats.whole_packets++;
		return IPA_NOT_FRAGMENTED;
	}

	/* Find an existing context or start a new one. */
	packet = ip_packet_find(ipv4);
	if (packet == NULL) {
		ip_packet_stats.too_many_packets++;
		return IPA_NO_MEMORY;
	}

	/* Don't attempt to assemble or account this packet anymore. */
	if (packet->flags & IP_PACKET_IGNORE)
		return IPA_IGNORED;

	/*
	 * Someone is trying to DoS us, so don't allocate more memory and wait
	 * them to go away. The periodic timer will clean up this memory later.
	 */
	if (packet->total_fragments > IPV4_MAXIMUM_FRAMENTS_AMOUNT) {
		packet->flags |= IP_PACKET_IGNORE;
		ip_packet_stats.too_many_fragments++;
		return IPA_TOO_MANY_FRAGMENTS;
	}

	/*
	 * Attempt to receive and assemble packet fragments.
	 *
	 * If the packet was already assembled it means we've got a repeated
	 * fragment and we should not bother the caller with it.
	 */
	if (!(packet->flags & IP_PACKET_COMPLETE)) {
		/*
		 * If not the first fragment, then skip header. Otherwise
		 * keep and account it.
		 *
		 * The first fragment contains the IP header with the options
		 * (if any) so we must account it and ignore the others.
		 */
		if (ipv4_fragment_offset(ipv4) > 0) {
			data += header_length;
			fragment_length -= header_length;
		} else
			packet->header_size = header_length;

		ip_packet_add_fragment(
			packet, header_length, ipv4_fragment_offset(ipv4) << 3,
			ipv4_more_fragments(ipv4), data, fragment_length);
		if (!(packet->flags & IP_PACKET_COMPLETE))
			return IPA_OK_INCOMPLETE;
	} else {
		ip_packet_stats.repeated_packet++;
		return IPA_REPEATED_PACKET;
	}

	*packetp = packet->data;
	*packetlen = packet->header_size + packet->total_size;

	/* Schedule clean up. */
	thread_add_event(packet_thread, ip_packet_cleanup_event, packet, 0,
			 &packet_cleanup_event);

	return IPA_OK;
}

/** Removes completed and used packets. */
static int ip_packet_periodic(struct thread *t __attribute__((unused)))
{
	time_t now;
	int index;

	/* Cache current time. */
	now = monotime(NULL);

	for (index = 0; index < PACKET_ASSEMBLY_IN_PROGRESS_MAX; index++) {
		/* Skip unused slots. */
		if (!(packet_list[index].flags & IP_PACKET_IN_USE))
			continue;

		/* Skip packet with recent activity. */
		if (packet_list[index].last_usage + IP_PACKET_INACTIVE_INTERVAL
		    >= now)
			continue;

		ip_packet_reset(&packet_list[index]);
	}

	/* Schedule next periodic clean up. */
	thread_add_timer(packet_thread, ip_packet_periodic, NULL,
			 IP_PACKET_INACTIVE_INTERVAL, &packet_cleanup_timer);

	return 0;
}

DEFUN(show_ip_packet_statistics, show_ip_packet_statistics_cmd,
      "show ip assembly",
      SHOW_STR
      IP_STR
      "IP fragmentation assembly statistics\n")
{
	vty_out(vty, "IP Assembly Statistics\n");
	vty_out(vty, "======================\n");
	vty_out(vty, "Invalid version: %Lu\n", ip_packet_stats.invalid_version);
	vty_out(vty, "Invalid header length: %Lu\n",
		ip_packet_stats.invalid_header_length);
	vty_out(vty, "Invalid packet length: %Lu\n",
		ip_packet_stats.invalid_packet_length);
	vty_out(vty, "Invalid checksum: %Lu\n",
		ip_packet_stats.invalid_checksum);
	vty_out(vty, "Fragment overlap: %Lu\n",
		ip_packet_stats.fragment_overlap);
	vty_out(vty, "Too many packets (no slots): %Lu\n",
		ip_packet_stats.too_many_packets);
	vty_out(vty, "Too many fragments: %Lu\n",
		ip_packet_stats.too_many_fragments);
	vty_out(vty, "Whole packets: %Lu\n", ip_packet_stats.whole_packets);
	vty_out(vty, "Assembled packets: %Lu\n",
		ip_packet_stats.assembled_packets);
	vty_out(vty, "Repeated packets: %Lu\n",
		ip_packet_stats.repeated_packet);
	vty_out(vty, "Huge packets: %Lu\n", ip_packet_stats.huge_packets);

	return CMD_SUCCESS;
}

DEFUN(show_ip_encap_packet_statistics, show_ip_encap_packet_statistics_cmd,
      "show ip-encap assembly",
      SHOW_STR
      "IP encapsulation information\n"
      "IP encapsulation statistics\n")
{
	vty_out(vty, "IP Encapsulation Statistics\n");
	vty_out(vty, "===========================\n");
	vty_out(vty, "Invalid version: %Lu\n",
		ip_encap_packet_stats.invalid_version);
	vty_out(vty, "Invalid header length: %Lu\n",
		ip_encap_packet_stats.invalid_header_length);
	vty_out(vty, "Invalid packet length: %Lu\n",
		ip_encap_packet_stats.invalid_packet_length);
	vty_out(vty, "Invalid checksum: %Lu\n",
		ip_encap_packet_stats.invalid_checksum);
	vty_out(vty, "Fragmented encapsulation packets (invalid): %Lu\n",
		ip_encap_packet_stats.fragmented);
	vty_out(vty, "Invalid encapsulation version: %Lu\n",
		ip_encap_packet_stats.invalid_encapsulation_version);
	vty_out(vty, "Invalid encapsulation magic: %Lu\n",
		ip_encap_packet_stats.invalid_encapsulation_magic);
	vty_out(vty, "Valid packets: %Lu\n",
		ip_encap_packet_stats.valid_packets);

	return CMD_SUCCESS;
}

void ip_fragmentation_handler_init(struct thread_master *tm)
{
	packet_thread = tm;
	thread_add_timer(packet_thread, ip_packet_periodic, NULL,
			 IP_PACKET_INACTIVE_INTERVAL, &packet_cleanup_timer);

	install_element(ENABLE_NODE, &show_ip_packet_statistics_cmd);
	install_element(ENABLE_NODE, &show_ip_encap_packet_statistics_cmd);
}

const char *ip_packet_assemble_result_str(enum ip_packet_assemble_result result)
{
#define MATCH_RETURN(value)                                                    \
	case (value):                                                          \
		return #value

	switch (result) {
		MATCH_RETURN(IPA_OK);
		MATCH_RETURN(IPA_OK_INCOMPLETE);
		MATCH_RETURN(IPA_INVALID_VERSION);
		MATCH_RETURN(IPA_INVALID_HEADER_LENGTH);
		MATCH_RETURN(IPA_INVALID_LENGTH);
		MATCH_RETURN(IPA_INVALID_CHECKSUM);
		MATCH_RETURN(IPA_FRAGMENT_OVERLAP);
		MATCH_RETURN(IPA_NO_MEMORY);
		MATCH_RETURN(IPA_TOO_MANY_FRAGMENTS);
		MATCH_RETURN(IPA_PACKET_TOO_BIG);
		MATCH_RETURN(IPA_NOT_FRAGMENTED);
		MATCH_RETURN(IPA_REPEATED_PACKET);
		MATCH_RETURN(IPA_IGNORED);
	default:
		return "unknown";
	}
}

enum ip_encap_packet_assemble_result
ipv4_encap_parse(const void *data, size_t datalen, struct ipv4_encap_result *rv)
{
	struct ipv4_encap_header *ipv4e = (struct ipv4_encap_header *)data;
	uint16_t header_length;
	uint16_t packet_length;
	int checksum;

	/* Reset result data structure. */
	memset(rv, 0, sizeof(*rv));

	/* Basic check: data size is at least the header. */
	if (datalen < sizeof(*ipv4e)) {
		ip_encap_packet_stats.invalid_header_length++;
		return IEPA_INVALID_HEADER_LENGTH;
	}

	/* Check version. */
	if (ipv4_version(&ipv4e->ipv4) != 4) {
		ip_encap_packet_stats.invalid_version++;
		return IEPA_INVALID_VERSION;
	}

	/* Check header length. */
	header_length = (uint16_t)ipv4_header_length(&ipv4e->ipv4);
	if (header_length < 20) {
		ip_encap_packet_stats.invalid_header_length++;
		return IEPA_INVALID_HEADER_LENGTH;
	}

	/* Verify checksum. */
	checksum = in_cksum(data, header_length);
	if (checksum) {
		ip_encap_packet_stats.invalid_checksum++;
		return IEPA_INVALID_CHECKSUM;
	}

	/* Check packet length. */
	packet_length = ntohs(ipv4e->ipv4.total_length);
	if (datalen < packet_length) {
		ip_packet_stats.invalid_packet_length++;
		return IEPA_INVALID_LENGTH;
	}

	/* Check if this packet is fragmented. */
	if (ipv4_more_fragments(&ipv4e->ipv4)
	    || ipv4_fragment_offset(&ipv4e->ipv4)) {
		ip_encap_packet_stats.fragmented++;
		return IEPA_FRAGMENTED;
	}

	/* Encapsulation check: version. */
	if (ipv4e->version != 0) {
		ip_encap_packet_stats.invalid_encapsulation_version++;
		return IEPA_INVALID_ENCAPSULATION_VERSION;
	}
	/* Encapsulation check: magic number. */
	if (ipv4e->magic != htonl(IP_ENCAP_MAGIC_VALUE)) {
		ip_encap_packet_stats.invalid_encapsulation_magic++;
		return IEPA_INVALID_ENCAPSULATION_MAGIC;
	}

	/* Set and return results. */
	rv->ifindex = ntohs(ipv4e->ifindex);
	rv->protocol = ipv4e->ipv4.protocol;
	rv->encap_length = header_length + IP_ENCAP_DATA_SIZE;
	rv->destination = ipv4e->ipv4.destination;

	/* Statistics. */
	ip_encap_packet_stats.valid_packets++;

	return IEPA_OK;
}

void ipv4_encap_output(const struct ipv4_encap_params *params, void *data,
		       size_t datalen)
{
	struct ipv4_encap_header *ipv4e = data;

	ipv4_set_version(&ipv4e->ipv4);
	/*
	 * NOTE: the encapsulation header does not count the encapsulation
	 *       data as part of the header.
	 */
	ipv4_set_header_length(&ipv4e->ipv4, sizeof(ipv4e->ipv4));
	ipv4e->ipv4.tos = IPV4_ENCAP_TOS;
	ipv4e->ipv4.id = htons(((uint16_t)frr_weak_random()));
	ipv4e->ipv4.total_length = htons(sizeof(*ipv4e) + datalen);
	ipv4e->ipv4.ttl = 1;
	ipv4e->ipv4.protocol = IP_ENCAP_ROUTING;
	ipv4e->ipv4.source = params->source;
	ipv4e->ipv4.destination = htonl(IPV4_ENCAP_DST);
	ipv4e->ipv4.checksum = 0;
	ipv4e->ipv4.checksum =
		(uint16_t)in_cksum(ipv4e, ipv4_header_length(&ipv4e->ipv4));

	ipv4e->version = 0;
	ipv4e->ifindex = htons((uint16_t)params->ifindex);
	ipv4e->magic = htonl(IP_ENCAP_MAGIC_VALUE);
}

ssize_t ipv4_output(const struct ipv4_output_params *params, const void *data,
		    size_t datalen)
{
	const uint8_t *packet_p = data;
	struct ipv4_header *ipv4e;
	struct ipv4_header *ipv4;
	struct udp_header *uh;
	size_t remaining = datalen;
	size_t data_size;
	size_t payload_size;
	size_t fragment_offset = 0;
	size_t headers_size;
	ssize_t bytes_sent;
	uint16_t more_fragments;
	bool first_fragment = true;
	struct sockaddr_in sin = {};
	struct msghdr msg = {};
	struct iovec iov[6] = {};
	uint8_t headers[128];

	/* Encapsulation header. */
	ipv4_encap_output(&params->encap, headers, datalen);
	ipv4e = (struct ipv4_header *)&headers[0];
	headers_size = ipv4_header_length(ipv4e) + sizeof(struct encap_header);

	/* Encapsulated header. */
	ipv4 = (struct ipv4_header *)&headers[headers_size];
	ipv4_set_version(ipv4);
	ipv4_set_header_length(ipv4, sizeof(struct ipv4_header));
	ipv4->tos = params->tos;
	ipv4->id = htons(((uint16_t)frr_weak_random()));
	ipv4->ttl = params->ttl;
	ipv4->protocol = params->protocol;
	ipv4->source = params->source;
	ipv4->destination = params->destination;
	ipv4->checksum = 0;

	headers_size += ipv4_header_length(ipv4);

	/* Encapsulated UDP. */
	if (params->protocol == IPPROTO_UDP) {
		uh = (struct udp_header *)&headers[headers_size];
		uh->source = params->udp_source;
		uh->destination = params->udp_destination;

		headers_size += sizeof(struct udp_header);
	}

	/* Destination: loopback. */
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(IPV4_ENCAP_DST);

	payload_size = params->mtu - headers_size;
	payload_size = payload_size - (payload_size % 8);

	while (remaining) {
		if (remaining > payload_size) {
			data_size = payload_size;
			more_fragments = IPV4_MORE_FRAGMENTS;
		} else {
			data_size = remaining;
			more_fragments = 0;
		}

		ipv4e->total_length =
			htons((uint16_t)(headers_size + (uint16_t)data_size));

		ipv4->fragmentation = htons(more_fragments
					    | (uint16_t)(fragment_offset >> 3));
		if (params->protocol == IPPROTO_UDP && first_fragment) {
			ipv4->total_length =
				htons(ipv4_header_length(ipv4)
				      + sizeof(struct udp_header) + data_size);
			uh->length =
				htons(sizeof(struct udp_header) + datalen);
		} else
			ipv4->total_length =
				htons((uint16_t)(ipv4_header_length(ipv4)
						 + data_size));

		ipv4e->checksum = 0;
		ipv4e->checksum = in_cksum(ipv4e, ipv4_header_length(ipv4e));
		ipv4->checksum = 0;
		ipv4->checksum = in_cksum(ipv4, ipv4_header_length(ipv4));

		iov[0].iov_base = headers;
		iov[0].iov_len = headers_size;
		iov[1].iov_base = (void *)(size_t)(packet_p + fragment_offset);
		iov[1].iov_len = data_size;

		msg.msg_iov = iov;
		msg.msg_iovlen = 2;
		msg.msg_name = &sin;
		msg.msg_namelen = sizeof(struct sockaddr_in);

		bytes_sent = sendmsg(params->socket, &msg, 0);
		if (bytes_sent == -1) {
			if (errno == EINTR || errno == EAGAIN
			    || errno == EWOULDBLOCK)
				continue;

			zlog_debug("%s: sendmsg: %s", __func__,
				   strerror(errno));
			return -1;
		}
		if (bytes_sent == 0) {
			zlog_debug("%s: sendmsg: connection closed", __func__);
			return 0;
		}

		remaining -= data_size;
		fragment_offset += data_size;

		if (first_fragment) {
			first_fragment = false;
			/* Only the first fragment has UDP header. */
			headers_size -= sizeof(struct udp_header);
			payload_size += sizeof(struct udp_header);
		}
	}

	return datalen;
}
