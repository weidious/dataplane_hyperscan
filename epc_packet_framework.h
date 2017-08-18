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

#ifndef __EPC_PACKET_FRAMEWORK_H__
#define __EPC_PACKET_FRAMEWORK_H__

/**
 * @file
 * This file contains data structure definitions to describe Data Plane
 * pipeline and function prototypes used to initialize pipeline.
 */
#include <rte_pipeline.h>

extern uint64_t num_dns_processed;
extern uint64_t drop;
extern uint64_t go;
/**
 * RTE Log type.
 */
#define RTE_LOGTYPE_EPC	RTE_LOGTYPE_USER1

/**
 * Number of ports.
 */
#define NUM_SPGW_PORTS		2

/**
 * Pipeline name size.
 */
#define PIPE_NAME_SIZE		80

/**
 * S1U port id.
 */
#define S1U_PORT_ID   0

/**
 * SGI port id.
 */

#define SGI_PORT_ID   1
/** DL Bearer Map key for hash lookup */
struct dl_bm_key {
	/** Ue ip */
	uint32_t ue_ipv4;
	/** Rule id */
	uint32_t rid;
};

/** Meta data used for directing packets to cores */
struct epc_meta_data {
	/** pipeline output port ID */
	uint32_t port_id;
	/** UE IPv4 hash for load balancing */
	uint32_t ue_ipv4_hash;
	/** flag for DNS pkt */
	uint32_t dns;
	/** eNB IP from GTP-U */
	uint32_t enb_ipv4;
	/** Teid from GTP-U */
	uint32_t teid;
	/** DL Bearer Map key */
	struct dl_bm_key key;
};

/*
 * Defines the frequency when each pipeline stage should be flushed.
 * For example,
 * 1 = flush the pipeline stage each time it is executed
 * 4 = flush the pipeline stage every four times it is executed
 * Generally "1" gives the best value for both performance
 * and latency, but under
 * certain circumstances (i.e. very small packets resulting in
 * very high packet rate)
 * a larger number may provide better overall CPU efficiency.
 */
#define EPC_PIPELINE_FLUSH_MAX	1

/*
 * Can only support as many lcores as the number of ports allowed in
 * a pipeline block
 */

#define DP_MAX_LCORE RTE_PIPELINE_PORT_OUT_MAX

/** Rx pipeline parameters - Per input port */
struct epc_rx_params {
	/** Count since last flush */
	int flush_count;
	/** Number of pipeline runs between flush */
	int flush_max;
	/** RTE pipeline params */
	struct rte_pipeline_params pipeline_params;
	/** Input port id */
	uint32_t port_in_id;
	/** Output port IDs  [0]-> load balance, [1]-> master
	  * control thr
	  */
	uint32_t port_out_id[2];
	/** Table ID - ports connect to this table */
	uint32_t table_id;
	/** RTE pipeline */
	struct rte_pipeline *pipeline;
	/** pipeline name */
	char name[PIPE_NAME_SIZE];
} __rte_cache_aligned;

/** Tx pipeline parameters - Per output port */
struct epc_tx_params {
	/** Count since last flush */
	int flush_count;
	/** Number of pipeline runs between flush */
	int flush_max;
	/** RTE pipeline params */
	struct rte_pipeline_params pipeline_params;
	/** Input port id */
	uint32_t port_in_id[DP_MAX_LCORE];
	/** Output port IDs */
	uint32_t port_out_id;
	/** Table ID - ports connect to this table */
	uint32_t table_id;
	/** RTE pipeline */
	struct rte_pipeline *pipeline;
	/** pipeline name */
	char name[PIPE_NAME_SIZE];
} __rte_cache_aligned;

/** Load Balance pipeline parameters - Per output port */
struct epc_load_balance_params {
	/** Count since last flush */
	int flush_count;
	/** Number of pipeline runs between flush */
	int flush_max;
	/** RTE pipeline params */
	struct rte_pipeline_params pipeline_params;
	/** Input port id */
	uint32_t port_in_id[NUM_SPGW_PORTS];
	/** Output port IDs */
	uint32_t port_out_id[DP_MAX_LCORE][NUM_SPGW_PORTS];
	/** Both input ports connect to this table, default entry uses metadata
	  * to decide output port
	  */
	uint32_t table_id;
	/** RTE pipeline */
	struct rte_pipeline *pipeline;
	/** pipeline name */
	char name[PIPE_NAME_SIZE];
} __rte_cache_aligned;

/** Worker pipeline parameters - Per output port */
struct epc_worker_params {
	/** Count since last flush */
	int flush_count;
	/** Number of pipeline runs between flush */
	int flush_max;
	/** RTE pipeline params */
	struct rte_pipeline_params pipeline_params;
	/** Input port id */
	uint32_t port_in_id[NUM_SPGW_PORTS];
	/** Output port IDs */
	uint32_t port_out_id[NUM_SPGW_PORTS];
	/** Table per input port, each table has a single entry,
	  * redirects the packet to the "other port", i.e.,
	  * packet from port 0 is directed to port 1 and
	  * vice/versa
	  */
	uint32_t table_id[NUM_SPGW_PORTS];
	/** RTE pipeline */
	struct rte_pipeline *pipeline;
	/** pipeline name */
	char name[PIPE_NAME_SIZE];
	/** Number of dns packets cloned by this worker */
	uint64_t num_dns_packets;
	uint64_t num_gets;

} __rte_cache_aligned;

typedef int (*epc_packet_handler) (struct rte_pipeline*, struct rte_mbuf **pkts,
		uint32_t n);

/* defines max number of pipelines per core */
#define EPC_PIPELINE_MAX	4
typedef void pipeline_func_t(void *param);

struct pipeline_launch {
	pipeline_func_t *func;	/* pipeline function called */
	void *arg;		/* pipeline function argument */
};

struct epc_lcore_config {
	int allocated;		/* indicates a number of pipelines enebled */
	struct pipeline_launch launch[EPC_PIPELINE_MAX];
};

struct epc_app_params {
	/* CPU cores */
	struct epc_lcore_config lcores[DP_MAX_LCORE];
	int core_rx[NUM_SPGW_PORTS];
	int core_tx[NUM_SPGW_PORTS];
	int core_load_balance;
	int core_mct;
	int core_iface;
	int core_stats;
	int core_spns_dns;
	unsigned num_workers;
	unsigned worker_cores[DP_MAX_LCORE];

	/* Ports */
	uint32_t ports[NUM_SPGW_PORTS];
	uint32_t n_ports;
	uint32_t port_rx_ring_size;
	uint32_t port_tx_ring_size;

	/* Rx rings */
	struct rte_ring *epc_lb_rx[NUM_SPGW_PORTS];
	struct rte_ring *epc_mct_rx[NUM_SPGW_PORTS];
	struct rte_ring *epc_mct_spns_dns_rx;
	struct rte_ring *epc_work_rx[DP_MAX_LCORE][NUM_SPGW_PORTS];

	/* Tx rings */
	struct rte_ring *ring_tx[DP_MAX_LCORE][NUM_SPGW_PORTS];

	uint32_t ring_rx_size;
	uint32_t ring_tx_size;

	/* Burst sizes */
	uint32_t burst_size_rx_read;
	uint32_t burst_size_rx_write;
	uint32_t burst_size_worker_read;
	uint32_t burst_size_worker_write;
	uint32_t burst_size_tx_read;
	uint32_t burst_size_tx_write;

	/* Pipeline params */
	struct epc_load_balance_params lb_params;
	struct epc_tx_params tx_params[NUM_SPGW_PORTS];
	struct epc_rx_params rx_params[NUM_SPGW_PORTS];
	struct epc_worker_params worker[DP_MAX_LCORE];
} __rte_cache_aligned;

extern struct epc_app_params epc_app;

/**
 * Adds pipeline function to core's list of pipelines to run
 *
 * @param func
 *	Function to run
 *
 * @param arg
 *	Argument to pipeline function
 *
 * @param core
 *	Core to run pipeline function on
 */
void epc_alloc_lcore(pipeline_func_t func, void *arg, int core);

/**
 *  Initialize the load balance pipeline
 *
 *  @param param
 *	Pipeline parameters passed on to pipeline at runtime
 */
void epc_load_balance_init(struct epc_load_balance_params *param);

/**
 * Initializes Rx pipeline
 *
 * @param param
 *	Pipeline parameters passed on to pipeline at runtime
 *
 * @param core
 *	Core to run Rx pipeline, used to warn if this core and the NIC port_id
 *	are in different NUMA domains
 *
 * @param port_id
 *	Rx Port ID
 *
 */
void epc_rx_init(struct epc_rx_params *param, int core, uint8_t port_id);

/**
 * Initializes Tx pipeline
 *
 * @param param
 *	Pipeline parameters passed on to pipeline at runtime
 *
 * @param core
 *	Core to run the Tx pipeline, used to warn if this core
 * and the NIC port_id
 *	are in different NUMA domains
 *
 * @param port_id
 *	Tx Port ID
 *
 */
void epc_tx_init(struct epc_tx_params *param, int core, uint8_t port_id);

/**
 * Initializes arp icmp pipeline
 */
void epc_arp_icmp_init(void);

/**
 * Returns the mac address for an IP address, currently works only for directly
 * connected neighbours
 *
 * @param ipaddr
 *	IP address to lookup
 *
 * @param phy_port
 *	Identifies the port to which the IP address is connected to
 *
 * @param hw_addr
 *	Ethernet address returned
 *
 * @param nhip
 *	next-hop IP address
 *	Same as ip addr (for now)
 *
 */
int arp_icmp_get_dest_mac_address(const uint32_t ipaddr,
		const uint32_t phy_port,
		struct ether_addr *hw_addr, uint32_t *nhip);

/**
 * Initializes DNS processing resources
 *
 */
void epc_spns_dns_init(void);

/**
 * Initializes a worker pipeline
 *
 * @param worker_params
 *	pipeline parameters
 *
 * @param core
 *	core to run the pipeline, this parameter is used to identify the input
 *	queue for the pipeline
 *
 */
void epc_worker_core_init(struct epc_worker_params *worker_params, int core);

/**
 * Tx pipeline function
 *
 * @param args
 *	pipeline parameters
 */
void epc_tx(void *args);

/**
 * Rx pipeline function
 *
 * @param args
 *	Pipeline parameters
 */
void epc_rx(void *args);

/**
 * Worker core function
 *
 * @param args
 *	Pipeline parameters
 *
 */
void epc_worker_core(void *args);

/**
 * ARP/ICMP pipeline function
 */
void epc_arp_icmp(__rte_unused void *arg);

/**
 * Load balance pipeline function
 *
 * @param args
 *	Pipeline parameters
 */
void epc_load_balance(void *args);

/**
 * Initialize EPC packet framework
 *
 * @param s1u_port_id
 *	Port id for s1u interface assigned by rte
 * @param sgi_port_id
 *	Port id for sgi interface assigned by rte
 */
void epc_init_packet_framework(uint8_t s1u_port_id, uint8_t sgi_port_id);

/**
 * Registers a worker function that is executed from the pipeline
 *
 * @param f
 *	Function handler for packet processing
 * @param port
 *	Port to register the worker function for
 */
void register_worker(epc_packet_handler f, int port);

/**
 * Launches data plane threads to execute pipeline funcs
 */
void packet_framework_launch(void);

#endif /* __EPC_PACKET_FRAMEWORK_H__ */
