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
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_per_lcore.h>
#include <rte_port_ring.h>

#include "main.h"
#include "epc_packet_framework.h"

void epc_tx_init(struct epc_tx_params *param, int core, uint8_t port)
{
	unsigned i;
	struct rte_pipeline *p;
	int wr_core;

	if (rte_eth_dev_socket_id(port) != (int)lcore_config[core].socket_id) {
		RTE_LOG(WARNING, EPC,
			"location of the TX core for port=%d is not optimal\n",
			port);
		RTE_LOG(WARNING, EPC,
			"****** performance may be degradated !!!!!!!!!!! *************\n");
	}

	if (port != app.s1u_port && port != app.sgi_port)
		rte_panic("%s: Unknown port no %d", __func__, port);

	memset(param, 0, sizeof(*param));

	snprintf((char *)param->name, PIPE_NAME_SIZE, "epc_tx_%d", port);
	param->pipeline_params.socket_id = rte_socket_id();
	param->pipeline_params.name = param->name;

	p = rte_pipeline_create(&param->pipeline_params);
	if (p == NULL)
		rte_panic("%s: Unable to configure the pipeline\n", __func__);

		/* one tx_params queue per core */
	for (i = 0; i < epc_app.num_workers; ++i) {
		wr_core = epc_app.worker_cores[i];
		struct rte_port_ring_reader_params port_ring_params = {
			.ring = epc_app.ring_tx[wr_core][port]
		};

		struct rte_pipeline_port_in_params port_params = {
			.ops = &rte_port_ring_reader_ops,
			.arg_create = (void *)&port_ring_params,
			.burst_size = epc_app.burst_size_tx_read,
		};

		if (rte_pipeline_port_in_create
		    (p, &port_params, &param->port_in_id[i])) {
			rte_panic
			    ("%s: Unable to configure input port\n"
				"for ring TX %i\n", __func__, i);
		}
	}
	{
	/* read from mct core*/
		struct rte_port_ring_reader_params port_ring_params = {
			.ring = epc_app.ring_tx[epc_app.core_mct][port]
		};

		struct rte_pipeline_port_in_params port_params = {
			.ops = &rte_port_ring_reader_ops,
			.arg_create = (void *)&port_ring_params,
			.burst_size = epc_app.burst_size_tx_read,
		};

		if (rte_pipeline_port_in_create
		    (p, &port_params, &param->port_in_id[i])) {
			rte_panic
			    ("%s: Unable to configure input port\n"
				"for ring TX %i\n", __func__, i);
		}
	}

	{
		struct rte_port_ethdev_writer_nodrop_params port_ethdev_params = {
			.port_id = epc_app.ports[port],
			.queue_id = 0,
			.tx_burst_sz = epc_app.burst_size_tx_write,
			.n_retries = 0,
		};
		struct rte_pipeline_port_out_params port_params = {
			.ops = &rte_port_ethdev_writer_nodrop_ops,
			.arg_create = (void *)&port_ethdev_params
		};

		if (rte_pipeline_port_out_create
		    (p, &port_params, &param->port_out_id)) {
			rte_panic
			    ("%s: Unable to configure output port\n"
				"for port %d\n", __func__, epc_app.ports[port]);
		}
	}

	{
		struct rte_pipeline_table_params table_params = {
			.ops = &rte_table_stub_ops,
		};

		if (rte_pipeline_table_create
		    (p, &table_params, &param->table_id)) {
			rte_panic
			    ("%s: Unable to configure the hash table\n"
				" (with extend)\n", __func__);
		}
	}
	/* to process pkts from all workers and +1 to forward arpcimp pkts */
	for (i = 0; i < epc_app.num_workers + 1; ++i) {
		if (rte_pipeline_port_in_connect_to_table
		    (p, param->port_in_id[i], param->table_id)) {
			rte_panic
			    ("%s: Unable to connect\n"
				" input port %u to table %u\n",
			     __func__, param->port_in_id[i], param->table_id);
		}
	}

	{
		struct rte_pipeline_table_entry actions = {
			.action = RTE_PIPELINE_ACTION_PORT,
			.port_id = 0
		};
		struct rte_pipeline_table_entry *action_ptr;

		if (rte_pipeline_table_default_entry_add
		    (p, param->table_id, &actions, &action_ptr)) {
			rte_panic
			    ("%s: Unable to add default entry to table %u\n",
			     __func__, param->table_id);
		}
	}

	/* to process pkts from all workers and +1 to forward arpcimp pkts */
	for (i = 0; i < epc_app.num_workers + 1; ++i)
		rte_pipeline_port_in_enable(p, param->port_in_id[i]);

	if (rte_pipeline_check(p) < 0)
		rte_panic("%s: Pipeline consistency check failed\n", __func__);

	param->pipeline = p;
	param->flush_max = EPC_PIPELINE_FLUSH_MAX;
}

void epc_tx(void *args)
{
	struct epc_tx_params *param = (struct epc_tx_params *)args;

	rte_pipeline_run(param->pipeline);
	if (++param->flush_count >= param->flush_max) {
		rte_pipeline_flush(param->pipeline);
		param->flush_count = 0;
	}
}
