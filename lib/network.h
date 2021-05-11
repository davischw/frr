/*
 * Network library header.
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#ifndef _ZEBRA_NETWORK_H
#define _ZEBRA_NETWORK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <arpa/inet.h>

#include <stdbool.h>
#include <stdint.h>

/* Both readn and writen are deprecated and will be removed.  They are not
   suitable for use with non-blocking file descriptors.
 */
extern int readn(int, uint8_t *, int);
extern int writen(int, const uint8_t *, int);

/* Set the file descriptor to use non-blocking I/O.  Returns 0 for success,
   -1 on error. */
extern int set_nonblocking(int fd);

extern int set_cloexec(int fd);

/* Does the I/O error indicate that the operation should be retried later? */
#define ERRNO_IO_RETRY(EN)                                                     \
	(((EN) == EAGAIN) || ((EN) == EWOULDBLOCK) || ((EN) == EINTR))

extern float htonf(float);
extern float ntohf(float);

/**
 * Helper function that returns a random long value. The main purpose of
 * this function is to hide a `random()` call that gets flagged by coverity
 * scan and put it into one place.
 *
 * The main usage of this function should be for generating jitter or weak
 * random values for simple purposes.
 *
 * See 'man 3 random' for more information.
 *
 * \returns random long integer.
 */
static inline long frr_weak_random(void)
{
	/* coverity[dont_call] */
	return random();
}

/*
 * IP fragmentation/assembly API.
 */

/**
 * RFC 791 Section 3.1. Internet Header Format.
 *
 * Hosts must be prepared to accept datagrams of up to 576 octets.
 */
#define IPV4_MINIMUM_FRAGMENT_SIZE 576

/**
 * Maximum allowed IPv4 packet size (reassembled).
 */
#define IPV4_MAXIMUM_PACKET_SIZE 65535

/**
 * Maximum amount of fragments allowed to be queued for a single IPv4 packet.
 *
 * Reasoning:
 *
 *  Maximum packet size
 * --------------------- = 113.77
 * Minimum fragment size
 */
#define IPV4_MAXIMUM_FRAMENTS_AMOUNT 113

/**
 * Maximum number of allowed in progress fragmented packets.
 */
#define PACKET_ASSEMBLY_IN_PROGRESS_MAX 12

/**
 * Maximum inactive interval before getting free'd.
 */
#define IP_PACKET_INACTIVE_INTERVAL 4

/**
 * Possible IP assembly outcomes.
 */
enum ip_packet_assemble_result {
	/** Packet was successfully assembled. */
	IPA_OK = 0,
	/** Packet is still being assembled. */
	IPA_OK_INCOMPLETE,
	/** Invalid IP packet version. */
	IPA_INVALID_VERSION,
	/** Packet part has invalid length. */
	IPA_INVALID_HEADER_LENGTH,
	/** Packet part has invalid length. */
	IPA_INVALID_LENGTH,
	/** Packet checksum invalid. */
	IPA_INVALID_CHECKSUM,
	/** Fragment overlapped existing part. */
	IPA_FRAGMENT_OVERLAP,
	/** Not enough resources to reassemble packet. */
	IPA_NO_MEMORY,
	/** Too many IP fragments. */
	IPA_TOO_MANY_FRAGMENTS,
	/** Packet is too big (>65k) and can't be assembled. */
	IPA_PACKET_TOO_BIG,
	/** Not fragmented. */
	IPA_NOT_FRAGMENTED,
	/** Packet already got read. */
	IPA_REPEATED_PACKET,
	/** Ignored packet (its too big or too fragmented). */
	IPA_IGNORED,
};

/**
 * Possible IP encapsulation parse outcomes.
 */
enum ip_encap_packet_assemble_result {
	/** Packet was successfully assembled. */
	IEPA_OK = 0,
	/** Invalid IP packet version. */
	IEPA_INVALID_VERSION,
	/** Packet part has invalid length. */
	IEPA_INVALID_HEADER_LENGTH,
	/** Packet part has invalid length. */
	IEPA_INVALID_LENGTH,
	/** Packet checksum invalid. */
	IEPA_INVALID_CHECKSUM,
	/** Fragmented encapsulated packet. */
	IEPA_FRAGMENTED,
	/** Invalid encapsulation version. */
	IEPA_INVALID_ENCAPSULATION_VERSION,
	/** Invalid encapsulation magic. */
	IEPA_INVALID_ENCAPSULATION_MAGIC,
};

/**
 * Statistic counters for IP assembly/fragmentation.
 */
struct ip_packet_statistics {
	/** Invalid IP header version. */
	uint64_t invalid_version;
	/** Invalid header length: less than 5 octets (or 20 bytes). */
	uint64_t invalid_header_length;
	/** Invalid packet length: header says X but packet data is Y. */
	uint64_t invalid_packet_length;
	/** Invalid checksum. */
	uint64_t invalid_checksum;
	/** IP fragment overlaps detected: possible malicious user. */
	uint64_t fragment_overlap;
	/**
	 * We exceeded the amount of parallel packets being assembled.
	 *
	 * This is possible in two situations:
	 *  1. We are receiving too much traffic and most of it is fragmented.
	 *  2. We are being DDoS with fragmented packets using randomized IDs.
	 */
	uint64_t too_many_packets;
	/**
	 * Packets with fragment count exceeding IPV4_MAXIMUM_FRAMENTS_AMOUNT.
	 */
	uint64_t too_many_fragments;
	/** Packets that were not fragmented. */
	uint64_t whole_packets;
	/** Total amount of assembled packets. */
	uint64_t assembled_packets;
	/**
	 * Amount of packets repeated.
	 *
	 * This situation is either:
	 *  1. When repeated fragments were received.
	 *  2. We exceeded the transfer rate causing ID collision.
	 */
	uint64_t repeated_packet;
	/** Amount of packets that exceeded 65k size. */
	uint64_t huge_packets;
};

extern struct ip_packet_statistics ip_packet_stats;

/**
 * Parses and assembles the passed IPv4 packet (if fragmented).
 *
 * NOTE:
 * Don't keep the pointer to `packet` because it will be `free()`d once the
 * FRR thread scheduler is called.
 *
 * \param data the IPv4 packet raw data (with header).
 * \param datalen the IPv4 packet read length as returned by syscall.
 * \param packet pointer to return the assembled packet (only set if return
 *               value is `IPA_OK`).
 * \param packetlen pointer to return total packet length (header + data).
 * \returns one of `enum ip_packet_assemble_result` values.
 */
enum ip_packet_assemble_result ipv4_packet_assemble(const uint8_t *data,
						    size_t datalen,
						    const uint8_t **packet,
						    size_t *packetlen);

/** Converts enum value to string. */
const char *
ip_packet_assemble_result_str(enum ip_packet_assemble_result result);

/* Forward declaration. */
struct thread_master;

/** Initialize packet assembler API/periodic timers.  */
void ip_fragmentation_handler_init(struct thread_master *tm);

/*
 * IP encapsulation.
 */

/** Build OSPF with special IP encapsulation. */
#define OSPF_IP_ENCAP

/* Special IP encapsulation protocols. */
#define OSPF_IP_ENCAP_SPF       248
#define OSPF_IP_ENCAP_OTHER     249
#define OSPF_IP_ENCAP_DR        250

/** Encapsulation parse results.  */
struct ipv4_encap_result {
	/** Interface index the packet came from. */
	int32_t ifindex;
	/** Encapsulation header length. */
	uint16_t encap_length;
	/** Encapsulation protocol. */
	uint8_t protocol;
	/** Destination address header value. */
	uint32_t destination;
};

/**
 * Parses a raw packet and returns whether the encapsulated data is valid or
 * not.
 *
 * \param data raw packet pointer.
 * \param datalen raw packet length.
 * \param rv the results output.
 * \returns `IEPA_OK` on success otherwise one of the codes in
 *          `enum ip_encap_packet_assemble_result`.
 */
enum ip_encap_packet_assemble_result
ipv4_encap_parse(const void *data, size_t datalen,
		 struct ipv4_encap_result *rv);

/** Encapsulation parameters. */
struct ipv4_encap_params {
	/** Source address for the packet. */
	uint32_t source;
	/** Interface index. */
	int32_t ifindex;
	/** Protocol. */
	uint8_t protocol;
};

/**
 * Encapsulation data size.
 *
 * Use this value to reserve the appropriated buffer size to use with
 * `ip_encap_output`.
 */
#define IPV4_ENCAP_DATA_SIZE 28

/** Encapsulation destination address. */
#define IPV4_ENCAP_DST 0x7F8201FE

/**
 * Generates an encapsulation header and sets it in the packet pointed by
 * `data`.
 *
 * \param params the encapsulation data parameters.
 * \param data pointer to the data packet.
 * \param datalen the amount of data in the packet.
 */
void ipv4_encap_output(const struct ipv4_encap_params *params, void *data,
		       size_t datalen);

/**
 * Regular IPv4 header (simplified) from RFC 791 Section 3.1..
 */
struct ipv4_header {
	uint8_t version_ihl;
#define IPV4_VERSION 4
	uint8_t tos;
	uint16_t total_length;
	uint16_t id;
	uint16_t fragmentation;
#define IPV4_MORE_FRAGMENTS 0x2000
#define IPV4_DONT_FRAGMENT 0x4000
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t source;
	uint32_t destination;
};

static inline uint8_t ipv4_version(const struct ipv4_header *ipv4)
{
	return ipv4->version_ihl >> 4;
}

static inline void ipv4_set_version(struct ipv4_header *ipv4)
{
	ipv4->version_ihl = (ipv4->version_ihl & 0x0F) | (4 << 4);
}

static inline uint8_t ipv4_header_length(const struct ipv4_header *ipv4)
{
	return (ipv4->version_ihl & 0x0F) << 2;
}

static inline void ipv4_set_header_length(struct ipv4_header *ipv4,
					  size_t header_length)
{
	ipv4->version_ihl = (ipv4->version_ihl & 0xF0) | (header_length >> 2);
}

static inline bool ipv4_more_fragments(const struct ipv4_header *ipv4)
{
	return (ntohs(ipv4->fragmentation) & IPV4_MORE_FRAGMENTS)
	       == IPV4_MORE_FRAGMENTS;
}

static inline bool ipv4_dont_fragment(const struct ipv4_header *ipv4)
{
	return (ntohs(ipv4->fragmentation) & IPV4_DONT_FRAGMENT)
	       == IPV4_DONT_FRAGMENT;
}

static inline uint16_t ipv4_fragment_offset(const struct ipv4_header *ipv4)
{
	return ntohs(ipv4->fragmentation) & 0x1FFF;
}

/* Magic encapsulation header. */
struct ipv4_encap_header {
	struct ipv4_header ipv4;

	/** Encapsulation version. */
	uint16_t version;
	/** Interface index. */
	uint16_t ifindex;
	/** Magic version. */
	uint32_t magic;
};


/** Encapsulation data length. */
#define IP_ENCAP_DATA_SIZE                                                     \
	(sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t))

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_NETWORK_H */
