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

#include "rte_common.h"
#include "rte_string_fns.h"
#include "rte_ring.h"
#include "rte_pipeline.h"
#include "rte_lcore.h"
#include "rte_ethdev.h"
#include "rte_port_ring.h"
#include "rte_port_ethdev.h"
#include "rte_table_hash.h"
#include "rte_table_stub.h"
#include "rte_byteorder.h"
#include "rte_udp.h"
#include "rte_tcp.h"
#include "rte_jhash.h"
#include "rte_cycles.h"
#include "rte_malloc.h"

#include "epc_packet_framework.h"
#define RTE_LOGTYPE_DP RTE_LOGTYPE_USER1
#define OFFSET_PORT_ID	0


static inline void epc_lb_set_port_id(struct rte_mbuf *m, uint32_t port_id)
{
	struct epc_meta_data *meta_data =
	    (struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(m, 128);
	uint32_t *offset_port_id = &meta_data->port_id;
	uint32_t *ue_ipv4_hash_offset = &meta_data->ue_ipv4_hash;
	uint32_t core_id;

	if (rte_is_power_of_2(epc_app.num_workers))
		core_id = *ue_ipv4_hash_offset & (epc_app.num_workers - 1);
	else
		core_id = *ue_ipv4_hash_offset % (epc_app.num_workers);
	RTE_LOG(DEBUG, DP, "LB core_id %d selected, *ue hash offset %x\n",
			core_id, *ue_ipv4_hash_offset);
	*offset_port_id = port_id + (core_id << 1);
}
static int
epc_lb_action_handler(struct rte_pipeline *p, struct rte_mbuf **pkts,
			uint32_t n, void *arg)
{
	uint32_t i;

	RTE_SET_USED(p);
	RTE_SET_USED(arg);

	for (i = 0; i < n; i++) {
		struct rte_mbuf *m = pkts[i];

		epc_lb_set_port_id(m, (uint32_t) (uintptr_t) arg);
	}
	return 0;
}

/* initialize flow classification core */
void epc_load_balance_init(struct epc_load_balance_params *param)
{
	unsigned i;
	struct rte_pipeline *p;

	memset(param, 0, sizeof(*param));

	snprintf((char *)param->name, PIPE_NAME_SIZE, "load_balance");
	param->pipeline_params.socket_id = rte_socket_id();
	param->pipeline_params.name = param->name;
	param->pipeline_params.offset_port_id = 128;

	p = rte_pipeline_create(&param->pipeline_params);
	if (p == NULL)
		rte_panic("Unable to configure the pipeline\n");

	/* Input port configuration */
	for (i = 0; i < epc_app.n_ports; i++) {
		struct rte_port_ring_reader_params port_ring_params = {
			.ring = epc_app.epc_lb_rx[i]
		};

		struct rte_pipeline_port_in_params port_params = {
			.ops = &rte_port_ring_reader_ops,
			.arg_create = (void *)&port_ring_params,
			.f_action = epc_lb_action_handler,
			.arg_ah = (void *)(uintptr_t) i,
			.burst_size = epc_app.burst_size_rx_read
		};

		if (rte_pipeline_port_in_create
		    (p, &port_params, &param->port_in_id[i])) {
			rte_panic
			    ("Unable to configure input port for ring %d\n", i);
		}
	}

	/* Output port configuration */
	for (i = 0; i < epc_app.num_workers; i++) {
		unsigned core_id = epc_app.worker_cores[i];
		struct rte_port_ring_writer_params port_ring_params = {
#ifdef RX_LB_TX
			.ring = epc_app.ring_tx[i][1],
#else
			.ring = epc_app.epc_work_rx[core_id][0],
#endif
			.tx_burst_sz = epc_app.burst_size_rx_write
		};

		struct rte_pipeline_port_out_params port_params = {
			.ops = &rte_port_ring_writer_ops,
			.arg_create = (void *)&port_ring_params,
			.f_action = NULL,
			.arg_ah = NULL,
		};

		if (rte_pipeline_port_out_create
		    (p, &port_params, &param->port_out_id[core_id][0])) {
			rte_panic
			("%s: Unable to configure output port for ring RX %i\n",
			     __func__, i);
		}
#ifdef RX_LB_TX
		port_ring_params.ring = epc_app.ring_tx[i][0];
#else
		port_ring_params.ring = epc_app.epc_work_rx[core_id][1];
#endif
		if (rte_pipeline_port_out_create
		    (p, &port_params, &param->port_out_id[core_id][1])) {
			rte_panic
			("%s: Unable to configure output port for ring RX %i\n",
			     __func__, i);
		}
	}

	/* table configuration */
	/* Tables */
	struct rte_pipeline_table_params table_params = {
		.ops = &rte_table_stub_ops,
		.arg_create = NULL,
		.f_action_hit = NULL,
		.f_action_miss = NULL,
		.arg_ah = NULL,
		.action_data_size = 0,
	};

	int status = rte_pipeline_table_create(p,
					       &table_params,
					       &param->table_id);

	if (status) {
		rte_pipeline_free(p);
		return;
	}

	for (i = 0; i < epc_app.n_ports; i++) {
		int status = rte_pipeline_port_in_connect_to_table(p,
								   i,
								   param->
								   table_id);

		if (status) {
			rte_panic("failed to connect port %d to table\n", i);
			rte_pipeline_free(p);
			return;
		}
	}

	/* Add entries to tables */
	struct rte_pipeline_table_entry default_entry = {
		.action = RTE_PIPELINE_ACTION_PORT_META,
	};

	struct rte_pipeline_table_entry *default_entry_ptr;

	status = rte_pipeline_table_default_entry_add(p,
						      param->table_id,
						      &default_entry,
						      &default_entry_ptr);

	if (status) {
		rte_pipeline_free(p);
		return;
	}

	/* Enable input ports */
	for (i = 0; i < epc_app.n_ports; i++) {
		int status = rte_pipeline_port_in_enable(p, i);

		if (status) {
			rte_free(p);
			return;
		}
	}

	/* Check pipeline consistency */
	if (rte_pipeline_check(p) < 0) {
		rte_pipeline_free(p);
		rte_panic("%s: Pipeline consistency check failed\n", __func__);
	}

	param->pipeline = p;

	/* set flush option */
	param->flush_max = EPC_PIPELINE_FLUSH_MAX;

}

void epc_load_balance(void *args)
{
	struct epc_load_balance_params *param =
	    (struct epc_load_balance_params *)args;

	rte_pipeline_run(param->pipeline);
	if (++param->flush_count >= param->flush_max) {
		rte_pipeline_flush(param->pipeline);
		param->flush_count = 0;
	}
}
