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
#include "gtpu.h"

/**
 * Function to construct gtpu header.
 *
 * @param m
 *	m - mbuf pointer
 * @param teid
 *	teid - tunnel endpoint id
 * @param tpdu_len
 *	tpdu_len - length of tunneled pdu
 *
 * @return
 *	None
 */
static inline void
construct_gtpu_hdr(struct rte_mbuf *m, uint32_t teid, uint16_t tpdu_len)
{
	uint8_t *gpdu_hdr;

	/* Construct GPDU header. */
	gpdu_hdr = (uint8_t *) get_mtogtpu(m);

	*(gpdu_hdr++) = (GTPU_VERSION << 5) | (GTP_PROTOCOL_TYPE_GTP << 4);

	*(gpdu_hdr++) = GTP_GPDU;
	*((uint16_t *) gpdu_hdr) = htons(tpdu_len);
	gpdu_hdr += 2;

	*((uint32_t *) gpdu_hdr) = htonl(teid);
}

int decap_gtpu_hdr(struct rte_mbuf *m)
{
	void *ret;

	/* Remove the GPDU hdr = 8 Bytes, IPv4 hdr= 20 Bytes, UDP = 8 Bytes
	 *  from the tunneled packet.
	 * Note: the ether header must be updated before tx.
	 */
	ret = rte_pktmbuf_adj(m, GPDU_HDR_SIZE + UDP_HDR_SIZE + IPv4_HDR_SIZE);
	if (ret == NULL) {
		RTE_LOG(ERR, DP, "Error: Failed to remove GTPU header\n");
		return -1;
	}

	RTE_LOG(DEBUG, DP,
			"Decap: modified mbuf offset %d, data_len %d, pkt_len%d\n",
			m->data_off, m->data_len, m->pkt_len);
	return 0;
}

int encap_gtpu_hdr(struct rte_mbuf *m, uint32_t teid)
{
	uint8_t *pkt_ptr;
	uint16_t tpdu_len;

	tpdu_len = rte_pktmbuf_data_len(m);
	tpdu_len -= ETH_HDR_SIZE;
	/* Prepend GPDU hdr = 8 Bytes, IPv4 hdr= 20 Bytes,
	 * UDP = 8 Bytes to mbuf data in headroom.
	 */
	pkt_ptr =
		(uint8_t *) rte_pktmbuf_prepend(m,
				GPDU_HDR_SIZE + UDP_HDR_SIZE +
				IPv4_HDR_SIZE);
	if (pkt_ptr == NULL) {
		RTE_LOG(ERR, DP, "Error: Failed to add GTPU header\n");
		return -1;
	}
	RTE_LOG(DEBUG, DP,
			"Encap: modified mbuf offset %d, data_len %d, pkt_len %d\n",
			m->data_off, m->data_len, m->pkt_len);

	construct_gtpu_hdr(m, teid, tpdu_len);

	return 0;
}

uint32_t gtpu_inner_src_ip(struct rte_mbuf *m)
{
	uint8_t *pkt_ptr;
	struct ipv4_hdr *inner_ipv4_hdr;

	pkt_ptr = (uint8_t *) get_mtogtpu(m);
	pkt_ptr += GPDU_HDR_SIZE;
	inner_ipv4_hdr = (struct ipv4_hdr *)pkt_ptr;

	return inner_ipv4_hdr->src_addr;
}
