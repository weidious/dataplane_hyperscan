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
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_port_ring.h>

#include "epc_packet_framework.h"

static epc_packet_handler epc_worker_func[NUM_SPGW_PORTS];

static inline int port_in_func(struct rte_pipeline *p, struct rte_mbuf **pkts,
		uint32_t n, void *arg)
{
	RTE_SET_USED(p);
	int portno = (uintptr_t) arg;
	epc_packet_handler f = epc_worker_func[portno];

	return f(p, pkts, n);
}

void epc_worker_core_init(struct epc_worker_params *param, int core)
{
	unsigned i;
	struct rte_pipeline *p;

	memset(param, 0, sizeof(*param));

	snprintf((char *)param->name, PIPE_NAME_SIZE, "epc_worker_%d", core);
	param->pipeline_params.socket_id = rte_socket_id();
	param->pipeline_params.name = param->name;

	p = rte_pipeline_create(&param->pipeline_params);
	if (p == NULL)
		rte_panic("Unable to configure the pipeline\n");

	for (i = 0; i < epc_app.n_ports; i++) {
		struct rte_port_ring_reader_params port_ring_params = {
			.ring = epc_app.epc_work_rx[core][i],
		};

		struct rte_pipeline_port_in_params port_params = {
			.ops = &rte_port_ring_reader_ops,
			.arg_create = (void *)&port_ring_params,
			.f_action = port_in_func,
			.arg_ah = (void *)(uintptr_t) i,
			.burst_size = epc_app.burst_size_worker_read
		};

		if (rte_pipeline_port_in_create
				(p, &port_params, &param->port_in_id[i])) {
			rte_panic
				("Unable to configure input port\n"
					" for ring %d\n", i);
		}
	}

	for (i = 0; i < epc_app.n_ports; i++) {
		struct rte_port_ring_writer_params port_ring_params = {
			.ring = epc_app.ring_tx[core][i],
			.tx_burst_sz = epc_app.burst_size_worker_write,
		};

		struct rte_pipeline_port_out_params port_params = {
			.ops = &rte_port_ring_writer_ops,
			.arg_create = (void *)&port_ring_params,
		};

		if (rte_pipeline_port_out_create
				(p, &port_params, &param->port_out_id[i])) {
			rte_panic
				("%s: Unable to configure output port\n"
					" for ring tx %i\n",
				 __func__, i);
		}
	}

	for (i = 0; i < epc_app.n_ports; i++) {
		struct rte_pipeline_table_params table_params = {
			.ops = &rte_table_stub_ops,
		};
		int status = rte_pipeline_table_create(p,
				&table_params,
				&param->table_id[i]);

		if (status) {
			rte_pipeline_free(p);
			rte_panic("%s: Unable to create the pipeline table\n",
					__func__);
		}
	}

	for (i = 0; i < epc_app.n_ports; i++) {
		int status = rte_pipeline_port_in_connect_to_table(p,
				i,
				param->
				table_id[i]);

		if (status) {
			rte_pipeline_free(p);
			rte_panic
			    ("%s: Unable to add default entry to table %u\n",
			     __func__, param->table_id[i]);
		}
	}

	for (i = 0; i < epc_app.n_ports; i++) {
		struct rte_pipeline_table_entry default_entry = {
			.action = RTE_PIPELINE_ACTION_PORT,
			{.port_id = !i},
		};

		struct rte_pipeline_table_entry *default_entry_ptr;

		int status = rte_pipeline_table_default_entry_add(p,
				param->
				table_id[i],
				&default_entry,
				&default_entry_ptr);

		if (status) {
			rte_pipeline_free(p);
			rte_panic
			    ("%s: Unable to add default entry to table %u\n",
			     __func__, param->table_id[i]);
		}
	}

	for (i = 0; i < epc_app.n_ports; i++) {
		int status = rte_pipeline_port_in_enable(p, i);

		if (status) {
			rte_pipeline_free(p);
			rte_panic("%s: Unable to enable in port\n", __func__);
		}
	}

	if (rte_pipeline_check(p) < 0) {
		rte_pipeline_free(p);
		rte_panic("%s: Pipeline consistency check failed\n", __func__);
	}

	param->pipeline = p;
	param->flush_max = EPC_PIPELINE_FLUSH_MAX;
}

void epc_worker_core(void *args)
{
	struct epc_worker_params *param = (struct epc_worker_params *)args;

	rte_pipeline_run(param->pipeline);
	if (++param->flush_count >= param->flush_max) {
		rte_pipeline_flush(param->pipeline);
		param->flush_count = 0;
	}
}

void register_worker(epc_packet_handler f, int port)
{
	unsigned i;

	for (i = 0; i < epc_app.num_workers; i++)
		epc_worker_func[port] = f;
}
