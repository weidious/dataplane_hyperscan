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
#include <string.h>
#include <sched.h>
#include <unistd.h>

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
#include <rte_port_ring.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_debug.h>
#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_socket.h>
#include <cmdline.h>

#include "main.h"
#include "stats.h"
#include "epc_packet_framework.h"
#include "interface.h"
#include "meter.h"
#include "acl.h"
#include "commands.h"

#ifdef MTR_STATS

#define MAX_FLOW_PER_UE 6

static void display_mtr_stats(void)
{
	int i, j;

	for (i = 0; i < MAX_UE; i++)
		for (j = 0; j < MAX_FLOW_PER_UE; j++) {
			if (sdf_stats_outcolor[i][j][0]
					|| sdf_stats_outcolor[i][j][1]) {

				printf("%10s %10s %10s %10s %10s %10s %10s %10s"
					" %10s %10s\n",	"UeID", "SDFIdx",
					"SDF_S", "ACL_S", "GREEN", "YELLOW",
					"RED", "DROP", "S1U_RX", "SGI_RX");
				printf("InColor:\n");
				printf("%10d %10d %10lu %10lu %10" PRIu64 " %10"
					PRIu64 " %10" PRIu64 " %10" PRIu64 " %10"
					PRIu64 " %10" PRIu64 "\n", i, j,
					sdf_idx_stats[i][j] / TIMER_INTERVAL,
					acl_rule_stats[j] / TIMER_INTERVAL,
					sdf_stats_incolor[i][j][0] / TIMER_INTERVAL,
					sdf_stats_incolor[i][j][1] / TIMER_INTERVAL,
					sdf_stats_incolor[i][j][2] / TIMER_INTERVAL,
					sdf_stats_incolor[i][j][3] / TIMER_INTERVAL,
					s1u_rx_stats / TIMER_INTERVAL,
					sgi_rx_stats / TIMER_INTERVAL);
				printf("OuColor:\n");
				printf("%10d %10d %10d %10d %10" PRIu64 " %10"
					PRIu64 " %10" PRIu64 " %10" PRIu64
					" %10d %10d\n", i, j, 0, 0,
					sdf_stats_outcolor[i][j][0] / TIMER_INTERVAL,
					sdf_stats_outcolor[i][j][1] / TIMER_INTERVAL,
					sdf_stats_outcolor[i][j][2] / TIMER_INTERVAL,
					sdf_stats_outcolor[i][j][3] / TIMER_INTERVAL,
					0, 0);
				printf(" Action:\n");
				printf("%10d %10d %10d %10d %10" PRIu64 " %10"
					PRIu64 " %10" PRIu64 " %10" PRIu64
					" %10d %10d\n", i, j, 0, 0,
					sdf_stats_action[i][j][0] / TIMER_INTERVAL,
					sdf_stats_action[i][j][1] / TIMER_INTERVAL,
					sdf_stats_action[i][j][2] / TIMER_INTERVAL,
					sdf_stats_action[i][j][3] / TIMER_INTERVAL,
					0, 0);
				sdf_stats_incolor[i][j][0] =
					sdf_stats_incolor[i][j][1] =
					sdf_stats_incolor[i][j][2] = 0;
				sdf_stats_outcolor[i][j][0] =
					sdf_stats_outcolor[i][j][1] =
					sdf_stats_outcolor[i][j][2] = 0;
				sdf_stats_action[i][j][0] =
					sdf_stats_action[i][j][1] =
					sdf_stats_action[i][j][2] = 0;
				sdf_idx_stats[i][j] = 0;
				acl_rule_stats[j] = 0;
				s1u_rx_stats = sgi_rx_stats = 0;
			}	/* if */

		}	/* for j */

}

#endif /* MTR_STATS */

#ifdef STATS

void
display_pip_istats(struct rte_pipeline *p, char *name, uint8_t port_id)
{
	int status;
	struct rte_pipeline_port_in_stats istats;
#ifdef STATS_CLR
	/* set clear bit */
	status = rte_pipeline_port_in_stats_read(p, port_id, &istats, 1);
#else
	status = rte_pipeline_port_in_stats_read(p, port_id, &istats, 0);
#endif
	if (status != 0)
		printf(" Stats read error\n");

	printf(" %15s IN_Ring%2d n_pkts_in:              %10" PRIu64
			"    n_pkts_drop: %10" PRIu64
			"    n_pkts_dropped_by_ah: %10"
			PRIu64 "\n", name, port_id, istats.stats.n_pkts_in,
			istats.stats.n_pkts_drop, istats.n_pkts_dropped_by_ah);
}

void display_pip_ictrs(void)
{
	uint32_t i = 0;

	printf("----- Ring IN counters ------\n");
	display_pip_istats(epc_app.rx_params[0].pipeline,
			epc_app.rx_params[0].name, 0);
	display_pip_istats(epc_app.rx_params[1].pipeline,
			epc_app.rx_params[1].name, 0);

	display_pip_istats(epc_app.lb_params.pipeline, epc_app.lb_params.name,
			0);
	display_pip_istats(epc_app.lb_params.pipeline, epc_app.lb_params.name,
			1);

	for (i = 0; i < epc_app.num_workers; i++) {
		display_pip_istats(epc_app.worker[i].pipeline,
				epc_app.worker[i].name, 0);
		display_pip_istats(epc_app.worker[i].pipeline,
				epc_app.worker[i].name, 1);
	}

	for (i = 0; i < epc_app.num_workers; i++) {
		display_pip_istats(epc_app.tx_params[0].pipeline,
				epc_app.tx_params[0].name, i);
		display_pip_istats(epc_app.tx_params[1].pipeline,
				epc_app.tx_params[1].name, i);
	}
}

#endif /* STATS */
#ifdef OSTATS
void
display_pip_ostats(struct rte_pipeline *p, char *name, uint8_t port_id)
{
	int status;
	struct rte_pipeline_port_out_stats ostats;

	status = rte_pipeline_port_out_stats_read(p, port_id, &ostats, 0);
	if (status != 0)
		printf(" Stats read error\n");
	printf(" %15s OUT_Ring%2d n_pkts_out:              %10" PRIu64
			"    n_pkts_drop: %10" PRIu64
			"    n_pkts_dropped_by_ah: %10"
			PRIu64 "\n", name, port_id, ostats.stats.n_pkts_in,
			ostats.stats.n_pkts_drop, ostats.n_pkts_dropped_by_ah);
}

void
display_pip_octrs(void)
{
	uint32_t i = 0;

	printf("----- Ring OUT counters ------\n");
	display_pip_ostats(epc_app.rx_params[0].pipeline,
			epc_app.rx_params[0].name, 0);
	display_pip_ostats(epc_app.rx_params[1].pipeline,
			epc_app.rx_params[1].name, 0);

	for (i = 0; i < epc_app.num_workers; i++) {
		unsigned core_id = epc_app.worker_cores[i];
		display_pip_ostats(epc_app.lb_params.pipeline,
				epc_app.lb_params.name,
				epc_app.lb_params.port_out_id[core_id][0]);
		display_pip_ostats(epc_app.lb_params.pipeline,
				epc_app.lb_params.name,
				epc_app.lb_params.port_out_id[core_id][1]);
	}

	for (i = 0; i < epc_app.num_workers; i++) {
		display_pip_ostats(epc_app.worker[i].pipeline,
				epc_app.worker[i].name, 0);
		display_pip_ostats(epc_app.worker[i].pipeline,
				epc_app.worker[i].name, 1);
	}

	display_pip_ostats(epc_app.tx_params[0].pipeline,
			epc_app.tx_params[0].name, 0);
	display_pip_ostats(epc_app.tx_params[1].pipeline,
			epc_app.tx_params[1].name, 0);

}
#endif
#ifdef DNS_STATS
void
display_dns_stats(void)
{
	uint32_t i = 0;

//	printf("----- DNS counters ------\n");
/*
	for (i = 0; i < epc_app.num_workers; i++)
		printf(" %15s DNS-packets received:       %10" PRIu64"\n",
			epc_app.worker[i].name,
			epc_app.worker[i].num_dns_packets);
	printf(" DNS-packets processed:       %10" PRIu64"\n",
				num_dns_processed);
	
*/
	printf("\n\n\n----- Total pkt counters ------\n");
	for (i = 0; i < epc_app.num_workers; i++)
		printf(" %15s Total packets received:       %10" PRIu64"\n",
			epc_app.worker[i].name,
			epc_app.worker[i].num_gets);
	printf(" Packets processed droped:       %10" PRIu64"\n",drop);
	printf(" Packets processed processed:       %10" PRIu64"\n",go);
	
}
#endif
#ifdef AH_STATS
void display_ah_ctrs(void)
{
	uint32_t i, j;

	for (i = 0; i < NUM_SPGW_PORTS; i++) {
		printf("  epc_rx_ctrs[%d]:          %10" PRIu64 "\n",
				i, epc_app.epc_rx_ctrs[i]);
		printf("  epc_lb_rx_ctrs[%d]:       %10" PRIu64 "\n",
				i, epc_app.epc_lb_rx_ctrs[i]);

		for (j = 0; j < epc_app.num_workers; j++) {
			uint8_t core = epc_app.worker_cores[j];
			printf("  epc_work_rx_ctrs[%d][%d]: %10" PRIu64 "\n", core,
					i, epc_app.epc_work_rx_ctrs[core][i]);
			printf("  epc_work_tx_ctrs[%d][%d]: %10" PRIu64 "\n", core,
					i, epc_app.epc_work_tx_ctrs[core][i]);
		}
		printf("  epc_tx_ctrs[%d]:          %10" PRIu64 "\n",
				i, epc_app.epc_tx_ctrs[i]);
	}

}
#endif

#ifdef INSTMNT

uint64_t diff_tsc_wrkr, total_wrkr_pkts_processed;
uint32_t flag_wrkr_update_diff;

void display_instmnt_wrkr(void)
{
	printf("  Total cycles taken by wrkr:      %10" PRIu64 "\n",
			diff_tsc_wrkr);

	printf("  Total pkts processed by wrkr: %10" PRIu64 "\n",
			total_wrkr_pkts_processed);

	if (total_wrkr_pkts_processed)
		printf("  Process cycles per packet:      %10" PRIu64 "\n",
				diff_tsc_wrkr / total_wrkr_pkts_processed);

}
#endif
#ifdef STATS
void display_nic_stats(void)
{
	struct rte_eth_stats stats0;
	struct rte_eth_stats stats1;
	static const char *nic_stats_border = "########################";

	rte_eth_stats_get(app.s1u_port, &stats0);
	rte_eth_stats_get(app.sgi_port, &stats1);
	{
		printf("\n  %s NIC statistics for port %s %s\n",
				nic_stats_border, "s1u_port", nic_stats_border);

		printf("  RX-packets:              %10" PRIu64
				"    RX-errors: %10" PRIu64
				"    RX-bytes: %10" PRIu64
				"\n", stats0.ipackets,
				stats0.ierrors, stats0.ibytes);
		printf("  RX-nombuf:               %10" PRIu64
				"	 RX-imissed:%10" PRIu64"\n",
				stats0.rx_nombuf, stats0.imissed);
		printf("  TX-packets:              %10" PRIu64
				"    TX-errors: %10" PRIu64
				"    TX-bytes: %10" PRIu64
				"\n", stats0.opackets,
				stats0.oerrors, stats0.obytes);
	}
	{
		printf("\n  %s NIC statistics for port %s %s\n",
				nic_stats_border, "sgi_port", nic_stats_border);

		printf("  RX-packets:              %10" PRIu64
				"    RX-errors: %10" PRIu64
				"    RX-bytes: %10" PRIu64
				"\n", stats1.ipackets,
				stats1.ierrors, stats1.ibytes);
		printf("  RX-nombuf:               %10" PRIu64
				"	 RX-imissed:%10" PRIu64"\n",
				stats1.rx_nombuf, stats1.imissed);
		printf("  TX-packets:              %10" PRIu64
				"    TX-errors: %10" PRIu64
				"    TX-bytes: %10" PRIu64
				"\n", stats1.opackets,
				stats1.oerrors, stats1.obytes);
	}
#ifdef STATS_CLR
	printf(" %10" PRIu64 " %10" PRIu64 " %10" PRIu64 " %10" PRIu64
			" %10" PRIu64 " %10" PRIu64 " %10" PRIu64
			" %10" PRIu64 "\n",
			stats0.ipackets, stats0.ierrors,
			stats1.opackets, stats1.oerrors,
			stats1.ipackets, stats1.ierrors,
			stats0.opackets, stats0.oerrors);

	rte_eth_stats_reset(app.s1u_port);
	rte_eth_stats_reset(app.sgi_port);
#endif /* STATS_CLR */
}

#endif /*STATS*/

#ifndef CMDLINE_STATS
static void timer_cb(__attribute__ ((unused))
		struct rte_timer *tim, __attribute__ ((unused))void *arg)
{
	static unsigned counter;
	unsigned lcore_id = rte_lcore_id();

#ifdef STATS
	//display_nic_stats();

	//display_pip_ictrs();

#ifdef OSTATS
	display_pip_octrs();
#endif
#ifdef DNS_STATS
	display_dns_stats();
#endif

#ifdef INSTMNT
	display_instmnt_wrkr();
#endif
#ifdef AH_STATS
	display_ah_ctrs();
#endif
#ifdef MTR_STATS
	display_mtr_stats();
#endif
#endif	/* STATS */
	/* this timer is automatically reloaded until we decide to
	 * stop it, when counter reaches 20. */
	if ((counter++) == 200)
		rte_timer_stop(tim);
}
#endif


#define TIMER_RESOLUTION_CYCLES 20000000ULL	/* around 10ms at 2 Ghz */
#define TIMER_INTERVAL 10	/* sec */

#ifndef CMDLINE_STATS
static struct rte_timer timer0;
uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
#endif



void epc_stats_core(__rte_unused void *args)
{

#ifdef CMDLINE_STATS
	struct cmdline *cl = NULL;
	int status;
	static int cmd_ready;

	if (cmd_ready == 0) {
		cl = cmdline_stdin_new(main_ctx, "vepc>");
		if (cl == NULL)
			rte_panic("Cannot create cmdline instance\n");
		cmdline_interact(cl);
		cmd_ready = 1;
	}

	status = cmdline_poll(cl);
	if (status < 0)
		rte_panic("CLI poll error (%" PRId32 ")\n", status);
	else if (status == RDLINE_EXITED) {
		cmdline_stdin_exit(cl);
		rte_exit(0, NULL);
	}

#else
	uint64_t hz;
	unsigned lcore_id;
	/* init timer structures */
	rte_timer_init(&timer0);

	/* load timer0, every second, on master lcore, reloaded automatically */
	hz = rte_get_timer_hz();
	lcore_id = rte_lcore_id();
	rte_timer_reset(&timer0, hz * TIMER_INTERVAL, PERIODICAL, lcore_id,
			timer_cb, NULL);

	while (1) {
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
	}
#endif

}
