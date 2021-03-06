/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in
 *	 the documentation and/or other materials provided with the
 *	 distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *	 contributors may be used to endorse or promote products derived
 *	 from this software without specific prior written permission.
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
#include <string.h>
#include <sched.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>

#include <rte_string_fns.h>
#include <rte_ring.h>
#include <rte_pipeline.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_port_ring.h>
#include <rte_port_ethdev.h>
#include <rte_table_hash.h>
#include <rte_table_stub.h>
#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_udp.h>
#include <rte_mbuf.h>
#include <rte_hash_crc.h>
#include <rte_port_ring.h>

#include "epc_packet_framework.h"
#include "main.h"
#include "gtpu.h"

/* Borrowed from dpdk ip_frag_internal.c */
#define PRIME_VALUE	0xeaad8405

#ifndef SKIP_LB_GTPU_AH
static inline void epc_s1u_rx_set_port_id(struct rte_mbuf *m)
{
	uint8_t *m_data = rte_pktmbuf_mtod(m, uint8_t *);
	struct epc_meta_data *meta_data =
	    (struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(m,
							META_DATA_OFFSET);
	uint32_t *port_id_offset = &meta_data->port_id;
	uint32_t *ue_ipv4_hash_offset = &meta_data->ue_ipv4_hash;
	struct ipv4_hdr *ipv4_hdr =
	    (struct ipv4_hdr *)&m_data[sizeof(struct ether_hdr)];
	struct udp_hdr *udph;
	uint32_t ip_len;
	struct ether_hdr *eh = (struct ether_hdr *)&m_data[0];
	uint32_t ipv4_packet;

	ipv4_packet = (eh->ether_type == htons(ETHER_TYPE_IPv4));

	if (unlikely(m->ol_flags
		& (PKT_RX_L4_CKSUM_BAD
		| PKT_RX_IP_CKSUM_BAD))) {
		RTE_LOG(ERR, EPC, "Bad checksum\n");
		ipv4_packet = 0;
	}

	*port_id_offset = 1;

	if (likely(ipv4_packet && ipv4_hdr->next_proto_id == IPPROTO_UDP)) {
		ip_len = (ipv4_hdr->version_ihl & 0xf) << 2;
		udph =
		    (struct udp_hdr *)&m_data[sizeof(struct ether_hdr) +
					      ip_len];
		if (likely(udph->dst_port == htons(2152))) {
			/* TODO: Inner could be ipv6 ? */
			struct ipv4_hdr *inner_ipv4_hdr =
			    (struct ipv4_hdr *)RTE_PTR_ADD(udph,
							   UDP_HDR_SIZE +
							   sizeof(struct
								  gtpu_hdr));
			const uint32_t *p =
			    (const uint32_t *)&inner_ipv4_hdr->src_addr;
			RTE_LOG(DEBUG, EPC, "gtpu packet\n");
			*port_id_offset = 0;
#ifdef SKIP_LB_HASH_CRC
			*ue_ipv4_hash_offset = p[0] >> 24;
#else
			*ue_ipv4_hash_offset =
			    rte_hash_crc_4byte(p[0], PRIME_VALUE);
#endif
		}
	}
}

static int epc_s1u_rx_port_in_action_handler(struct rte_pipeline *p,
					struct rte_mbuf **pkts, uint32_t n,
					void *arg)
{
	uint32_t i;

	RTE_SET_USED(arg);
	RTE_SET_USED(p);

	for (i = 0; i < n; i++) {
		struct rte_mbuf *m = pkts[i];
#ifdef SKIP_RX_META
		RTE_SET_USED(m);
#else
		epc_s1u_rx_set_port_id(m);
#endif
	}
	return 0;
}
#endif				/*SKIP_LB_GTPU_AH */
static char ether_bcast_addr[] = {[0 ... 5] = 0xff };

static inline void epc_sgi_rx_set_port_id(struct rte_mbuf *m)
{
	uint8_t *m_data = rte_pktmbuf_mtod(m, uint8_t *);
	struct epc_meta_data *meta_data =
	    (struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(m,
							META_DATA_OFFSET);
	uint32_t *port_id_offset = &meta_data->port_id;
	uint32_t *ue_ipv4_hash_offset = &meta_data->ue_ipv4_hash;
	struct ipv4_hdr *ipv4_hdr =
	    (struct ipv4_hdr *)&m_data[sizeof(struct ether_hdr)];

	struct ether_hdr *eh = (struct ether_hdr *)&m_data[0];
	uint32_t ipv4_packet;
	uint32_t bcast;

	ipv4_packet = (eh->ether_type == htons(ETHER_TYPE_IPv4));
	bcast =
	    !memcmp(eh->d_addr.addr_bytes, ether_bcast_addr,
		    sizeof(ether_bcast_addr));

	if (unlikely(m->ol_flags
		& (PKT_RX_L4_CKSUM_BAD | PKT_RX_IP_CKSUM_BAD))) {
		RTE_LOG(DEBUG, EPC, "Bad checksum\n");
		/* put packets with bad checksum to kernel */
		ipv4_packet = 0;
	}

	*port_id_offset = ipv4_packet &&
			((ipv4_hdr->dst_addr != app.sgi_ip) && !bcast) ? 0 : 1;
	if (likely(!*port_id_offset)) {
		const uint32_t *p = (const uint32_t *)&ipv4_hdr->dst_addr;

		RTE_LOG(DEBUG, EPC, "SGI packet\n");
#ifdef SKIP_LB_HASH_CRC
		*ue_ipv4_hash_offset = p[0] >> 24;
#else
		*ue_ipv4_hash_offset = rte_hash_crc_4byte(p[0], PRIME_VALUE);
#endif
	}
}

static int
epc_sgi_rx_port_in_action_handler(struct rte_pipeline *p,
					struct rte_mbuf **pkts,
					  uint32_t n, void *arg)
{
	uint32_t i;

	RTE_SET_USED(arg);
	RTE_SET_USED(p);
	for (i = 0; i < n; i++) {
		struct rte_mbuf *m = pkts[i];
#ifdef SKIP_RX_META

		RTE_SET_USED(m);
#else
		epc_sgi_rx_set_port_id(m);
#endif
	}
	return 0;
}

void epc_rx_init(struct epc_rx_params *param, int core, uint8_t port_id)
{
	struct rte_pipeline *p;
	unsigned i;

	if (port_id != app.sgi_port && port_id != app.s1u_port)
		rte_panic("Unknown port id %d\n", port_id);

	memset(param, 0, sizeof(*param));

	snprintf((char *)param->name, PIPE_NAME_SIZE, "epc_rx_%d", port_id);
	param->pipeline_params.socket_id = rte_socket_id();
	param->pipeline_params.name = param->name;
	param->pipeline_params.offset_port_id = META_DATA_OFFSET;

	p = rte_pipeline_create(&param->pipeline_params);
	if (p == NULL)
		rte_panic("%s: Unable to configure the pipeline\n", __func__);

	if (rte_eth_dev_socket_id(port_id)
		!= (int)lcore_config[core].socket_id) {
		RTE_LOG(WARNING, EPC,
			"location of the RX core for port=%d is not optimal\n",
			port_id);
		RTE_LOG(WARNING, EPC,
			"***** performance may be degradated !!!!! *******\n");
	}

	struct rte_port_ethdev_reader_params port_ethdev_params = {
		.port_id = epc_app.ports[port_id],
		.queue_id = 0,
	};

	struct rte_pipeline_port_in_params port_params = {
		.ops = &rte_port_ethdev_reader_ops,
		.arg_create = (void *)&port_ethdev_params,
		.burst_size = epc_app.burst_size_rx_read,
	};
#ifndef SKIP_LB_GTPU_AH
	if (port_id == app.s1u_port)
		port_params.f_action = epc_s1u_rx_port_in_action_handler;
	else if (port_id == app.sgi_port)
#endif
		port_params.f_action = epc_sgi_rx_port_in_action_handler;

	if (rte_pipeline_port_in_create(p, &port_params, &param->port_in_id)) {
		rte_panic("%s: Unable to configure input port for port %d\n",
			  __func__, port_id);
	}

	for (i = 0; i < NUM_SPGW_PORTS; i++) {
		struct rte_port_ring_writer_params port_ring_params = {
			.tx_burst_sz = epc_app.burst_size_rx_write,
		};

		struct rte_pipeline_port_out_params port_params = {
			.ops = &rte_port_ring_writer_ops,
			.arg_create = (void *)&port_ring_params
		};

#ifdef RX_TX
		 /* push pkts on mct core rings.tx_core reads from these*/
		if (1)
			port_ring_params.ring = epc_app.ring_tx[epc_app.core_mct][port_id ^ 1];
#else
		if (i == 0)
			port_ring_params.ring = epc_app.epc_lb_rx[port_id];
#endif
		else
			port_ring_params.ring = epc_app.epc_mct_rx[port_id];

		if (rte_pipeline_port_out_create
		    (p, &port_params, &param->port_out_id[i])) {
			rte_panic
			    ("%s: Unable to configure output port\n"
				"for ring RX %i\n", __func__, i);
		}
	}

	{
		struct rte_pipeline_table_params table_params = {
			.ops = &rte_table_stub_ops
		};

		if (rte_pipeline_table_create
		    (p, &table_params, &param->table_id)) {
			rte_panic("%s: Unable to configure table %u\n",
				  __func__, param->table_id);
		}
	}

	if (rte_pipeline_port_in_connect_to_table
	    (p, param->port_in_id, param->table_id)) {
		rte_panic("%s: Unable to connect input port %u to table %u\n",
			  __func__, param->port_in_id, param->table_id);
	}

	{
		struct rte_pipeline_table_entry default_entry = {
			.action = RTE_PIPELINE_ACTION_PORT_META,
		};
		struct rte_pipeline_table_entry *default_entry_ptr;

		int status = rte_pipeline_table_default_entry_add(p,
				param->table_id,
				&default_entry,
				&default_entry_ptr);

		if (status) {
			rte_panic(
				"%s: failed to add table default entry\n",
				__func__);
			rte_pipeline_free(p);
			return;
		}
	}

	if (rte_pipeline_port_in_enable(p, param->port_in_id)) {
		rte_panic("%s: unable to enable input port %d\n", __func__,
			  param->port_in_id);
	}

	param->flush_max = EPC_PIPELINE_FLUSH_MAX;

	if (rte_pipeline_check(p) < 0)
		rte_panic("%s: Pipeline consistency check failed\n", __func__);

	param->pipeline = p;
}

void epc_rx(void *args)
{
	struct epc_rx_params *param = (struct epc_rx_params *)args;

	rte_pipeline_run(param->pipeline);
	if (++param->flush_count >= param->flush_max) {
		rte_pipeline_flush(param->pipeline);
		param->flush_count = 0;
	}
}
