/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2017 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __EPC_ARP_ICMP_H__
#define __EPC_ARP_ICMP_H__
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of ARP packet processing.
 */
#include <rte_ether.h>
#include <rte_rwlock.h>

/**
 * seconds between ARP request retransmission.
 */
#define ARP_TIMEOUT 2
/**
 * ring size.
 */
#define ARP_BUFFER_RING_SIZE 128
/**
 * ARP entry populated and echo reply received.
 */
#define COMPLETE   1
/**
 * ARP entry populated and awaiting ARP reply.
 */
#define INCOMPLETE 0
/**
 * set to enable debug.
 */
#define ARPICMP_DEBUG  0

/** Pipeline arguments */
struct pipeline_arp_icmp_in_port_h_arg {
	/** rte pipeline */
	struct  pipeline_arp_icmp *p;
	/** in port id */
	uint8_t in_port_id;
};

/**
 * print mac format.
 */
#define FORMAT_MAC  \
	"%02"PRIx8":" \
"%02"PRIx8":" \
"%02"PRIx8":" \
"%02"PRIx8":" \
"%02"PRIx8":" \
"%02"PRIx8
/**
 * print eth_addr.
 */
#define FORMAT_MAC_ARGS(eth_addr)  \
	(eth_addr).addr_bytes[0],  \
(eth_addr).addr_bytes[1],  \
(eth_addr).addr_bytes[2],  \
(eth_addr).addr_bytes[3],  \
(eth_addr).addr_bytes[4],  \
(eth_addr).addr_bytes[5]


/** IPv4 key for ARP table. */
struct pipeline_arp_icmp_arp_key_ipv4 {
	/** ipv4 address */
	uint32_t ip;
	/** port id */
	uint8_t port_id;
	/** key filler */
	uint8_t filler1;
	/** key filler */
	uint8_t filler2;
	/** key filler */
	uint8_t filler3;
};


/** ARP table entry. */

struct arp_entry_data {
	/** ether address */
	struct ether_addr eth_addr;
	/** port number */
	uint8_t port;
	/** status: COMPLETE/INCOMPLETE */
	uint8_t status;
	/** ipv4 address */
	uint32_t ip;
	/** last update time */
	time_t last_update;
	/** pkts queued */
	struct rte_ring *queue;
	/** queue lock */
	rte_rwlock_t queue_lock;
} __attribute__((packed));

/**
 * Print ARP packet.
 *
 * @param pkt
 *	ARP packet.
 *
 */
void print_pkt1(struct rte_mbuf *pkt);

/**
 * Send ARP request.
 *
 * @param port_id
 *	port id.
 * @param ip
 *	ip address to resolve the mac.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int send_arp_req(unsigned port_id, uint32_t ip);

/**
 * Retrieve MAC address.
 *
 * @param ipaddr
 *	dst IP address.
 * @param phy_port
 *	port no.
 * @param hw_addr
 *	mac address.
 * @param nhip
 *	next hop ip.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int arp_icmp_get_dest_mac_address(__rte_unused const uint32_t ipaddr,
		const uint32_t phy_port,
		struct ether_addr *hw_addr, uint32_t *nhip);

/**
 * Retrieve ARP entry.
 *
 * @param arp_key
 *	key.
 *
 * @return
 *	arp entry data if found.
 *	neg value if error.
 */
struct arp_entry_data *retrieve_arp_entry(
			const struct pipeline_arp_icmp_arp_key_ipv4 arp_key);

/**
 * Queue unresolved arp pkts.
 *
 * @param arp_data
 *	arp entry data.
 * @param m
 *	packet pointer.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int arp_queue_unresolved_packet(struct arp_entry_data *arp_data,
				struct rte_mbuf *m);

#endif /*__EPC_ARP_ICMP_H__ */
