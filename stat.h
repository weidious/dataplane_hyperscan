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

#define MAX_FLOW_PER_UE 6
extern uint64_t go;
extern uint64_t drop;
void
Idisplay_dns_stats(void)
{
        uint32_t i = 0;
	if(go>3100){
        printf("----- DNS counters ------\n");
        for (i = 0; i < epc_app.num_workers; i++)
                printf(" %15s DNS-packets received:       %10" PRIu64"\n",
                        epc_app.worker[i].name,
                        epc_app.worker[i].num_dns_packets);
        printf(" DNS-packets processed:       %10" PRIu64"\n",
                                num_dns_processed);

        printf("----- Total pkt counters ------\n");
        for (i = 0; i < epc_app.num_workers; i++)
                printf(" %15s Total packets received:       %10" PRIu64"\n",
                        epc_app.worker[i].name,
                        epc_app.worker[i].num_gets);
        printf(" Packets processed droped:       %10" PRIu64"\n",drop);
        printf(" Packets processed processed:       %10" PRIu64"\n",go);
	}
}

