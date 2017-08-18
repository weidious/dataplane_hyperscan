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

#ifndef _IPV4_H_
#define _IPV4_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of dataplane IPv4 header constructor.
 */
#include <stdint.h>
#include <rte_ip.h>
#include "main.h"
#include "util.h"

/**
 * Function to return pointer to ip headers, assuming ether header is untagged.
 *
 * @param m
 *	mbuf pointer
 *
 * @return
 *	pointer to ipv4 headers
 */
static inline struct ipv4_hdr *get_mtoip(struct rte_mbuf *m)
{
#ifdef DPDK_2_1
	return (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) +
				   ETH_HDR_SIZE);
#else
	return rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *,
				       sizeof(struct ether_hdr));
#endif

}

/**
 * Function to construct IPv4 header with default values.
 *
 * @param m
 *	mbuf pointer
 *
 * @return
 *	None
 */
static inline void build_ipv4_default_hdr(struct rte_mbuf *m)
{
	struct ipv4_hdr *ipv4_hdr;

	ipv4_hdr = get_mtoip(m);

	/* construct IPv4 header with hardcode values */
	ipv4_hdr->version_ihl = 0x45;
	ipv4_hdr->type_of_service = 0;
	ipv4_hdr->packet_id = 0x1513;
	ipv4_hdr->fragment_offset = 0;
	ipv4_hdr->time_to_live = 64;
	ipv4_hdr->total_length = 0;
	ipv4_hdr->next_proto_id = 0;
	ipv4_hdr->src_addr = 0;
	ipv4_hdr->dst_addr = 0;
}

/**
 * Function to construct IPv4 header with default values.
 *
 * @param m
 *	mbuf pointer
 * @param len
 *	len of header
 * @param protocol
 *	next protocol id
 * @param src_ip
 * @param dst_ip
 *
 * @return
 *	None
 */
static inline void
set_ipv4_hdr(struct rte_mbuf *m, uint16_t len, uint8_t protocol,
	     uint32_t src_ip, uint32_t dst_ip)
{
	struct ipv4_hdr *ipv4_hdr;

	ipv4_hdr = get_mtoip(m);

	/* Set IPv4 header values */
	ipv4_hdr->total_length = htons(len);
	ipv4_hdr->next_proto_id = protocol;
	ipv4_hdr->src_addr = htonl(src_ip);
	ipv4_hdr->dst_addr = htonl(dst_ip);

}

/**
 * Function to construct ipv4 header.
 *
 * @param m
 *	mbuf pointer
 * @param len
 *	len of header
 * @param protocol
 *	next protocol id
 * @param src_ip
 * @param dst_ip
 *
 * @return
 *	None
 */
void
construct_ipv4_hdr(struct rte_mbuf *m, uint16_t len, uint8_t protocol,
		   uint32_t src_ip, uint32_t dst_ip);

#endif				/* _IPV4_H_ */
