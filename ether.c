/*-
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

#include <arpa/inet.h>

#include <rte_ip.h>

#include "main.h"
#include "ether.h"
#include "util.h"
#include "ipv4.h"
#include "pipeline/epc_arp_icmp.h"

/**
 * Function to set ethertype.
 *
 * @param m
 *	mbuf pointer
 * @param type
 *	type
 *
 * @return
 *	None
 */
static inline void set_ether_type(struct rte_mbuf *m, uint16_t type)
{
	struct ether_hdr *eth_hdr = get_mtoeth(m);
	/* src/dst mac will be updated by send_to() */
	eth_hdr->ether_type = htons(type);
}

/**
 * Function to construct L2 headers.
 *
 * @param m
 *	mbuf pointer
 *
 * @return
 *	- 0  on success
 *	- -1 on failure (ARP lookup fail)
 */
int construct_ether_hdr(struct rte_mbuf *m, uint8_t portid)
{
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, void *);
	struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)&eth_hdr[1];
	struct arp_entry_data *ret_arp_data = NULL;
	struct pipeline_arp_icmp_arp_key_ipv4 tmp_arp_key = {
		.ip = ipv4_hdr->dst_addr,
		.port_id = portid,
		0, 0, 0 /* filler */
	};


	/* IPv4 L2 hdr */
	eth_hdr->ether_type = htons(ETH_TYPE_IPv4);

#ifdef SKIP_ARP_LOOKUP

	uint8_t i;

	for (i = 0; i < 6; i++)
		hw_addr.addr_bytes[i] = 0x00 + i;

#else				/* !SKIP_ARP_LOOKUP */

	if (ARPICMP_DEBUG)
		printf("arp_icmp_get_dest_mac_address search ip 0x%x\n",
								tmp_arp_key.ip);
#ifdef INDEX_ARP_LOOKUP
	if ((ipaddr & 0xff000000) == 0xb000000)
		ret_arp_data = &arp_index_dl[ipaddr & 0xfff];
	else
		ret_arp_data = &arp_index_ul[ipaddr & 0xfff];

	if (ret_arp_data->ip == ipaddr) {
		ether_addr_copy(&ret_arp_data->eth_addr, hw_addr);
		return 1;
	} else
		return 0;
#endif
	ret_arp_data = retrieve_arp_entry(tmp_arp_key);


	if (ret_arp_data == NULL) {
		RTE_LOG(DEBUG, DP, "%s: ARP lookup failed for ip 0x%x\n",
				__func__, tmp_arp_key.ip);
		return -1;
	}

	if (ret_arp_data->status == INCOMPLETE)	{
		if (arp_queue_unresolved_packet(ret_arp_data, m) == 0)
			return -1;
	}

	RTE_LOG(DEBUG, DP,
			"MAC found for ip %s"
			", port %d - %02x:%02x:%02x:%02x:%02x:%02x\n",
			inet_ntoa(*(struct in_addr *)&tmp_arp_key.ip), portid,
					ret_arp_data->eth_addr.addr_bytes[0],
					ret_arp_data->eth_addr.addr_bytes[1],
					ret_arp_data->eth_addr.addr_bytes[2],
					ret_arp_data->eth_addr.addr_bytes[3],
					ret_arp_data->eth_addr.addr_bytes[4],
					ret_arp_data->eth_addr.addr_bytes[5]);

#endif				/* SKIP_ARP_LOOKUP */

	ether_addr_copy(&ports_eth_addr[portid], &eth_hdr->s_addr);
	ether_addr_copy(&ret_arp_data->eth_addr, &eth_hdr->d_addr);

#ifdef INSTMNT
	flag_wrkr_update_diff = 1;
	total_wrkr_pkts_processed++;
#endif
	return 0;
}
