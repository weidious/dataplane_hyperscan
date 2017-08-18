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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <arpa/inet.h>

#include <rte_ethdev.h>

#include "main.h"
#include "pipeline/epc_packet_framework.h"

/* app config structure */
struct app_params app;

/* prints the usage statement and quits with an error message */
static inline void dp_print_usage(void)
{
	printf("\nDataplane supported command line arguments are:\n");
	printf
		("\n+-------------------+-------------+--------------------------------------------+");
	printf
		("\n| ARGUMENT %8s | PRESENCE    | DESCRIPTION                                |",
		 "");
	printf
		("\n+-------------------+-------------+--------------------------------------------+");
	printf
		("\n| --s1u_ip %8s | MANDATORY   | S1U IP address of the SGW.                 |",
		 "");
	printf
		("\n| --s1u_mac %7s | MANDATORY   | S1U port mac address of the SGW.           |",
		 "");
	printf
		("\n| --sgi_ip %8s | MANDATORY   | SGI IP address of the SGW.                 |",
		 "");
	printf
		("\n| --sgi_mac %7s | MANDATORY   | SGI port mac address of the PGW.           |",
		 "");
	printf
		("\n| --s1uc %10s | OPTIONAL    | core number to run s1u rx/tx.              |",
		 "");
	printf
		("\n| --sgic %10s | OPTIONAL    | core number to run sgi rx/tx.              |",
		 "");
	printf
		("\n| --bal %11s | OPTIONAL    | core number to run load balancer.          |",
		 "");
	printf
		("\n| --mct %11s | OPTIONAL    | core number to run mcast pkts.             |",
		 "");
	printf
		("\n| --iface %9s | OPTIONAL    | core number to run Interface for IPC.      |",
		 "");
	printf
		("\n| --stats %9s | OPTIONAL    | core number to run timer for stats.        |",
		 "");
	printf
		("\n| --num_workers %3s | MANDATORY   | no. of worker instances.                   |",
		 "");
	printf
		("\n| --log %11s | MANDATORY   | log level, 1- Notification, 2- Debug.      |",
		 "");
	printf
		("\n+-------------------+-------------+--------------------------------------------+");
	printf
		("\n\nExample Usage: \n$ ./build/ngic_dataplane -c 0xfff -n 4 -- --s1u_ip 11.1.1.100\
		 --s1u_mac 90:e2:ba:58:c8:64 --sgi_mac 90:e2:ba:58:c8:65 \
		 --sgi_ip 13.1.1.93 --s1uc 0 --sgic 1\
		 --bal 2 --mct 3 --iface 4 --stats 3 \
		 --num_workers 2 --log 1");
	printf("\n");
	exit(0);
}

/* parse ethernet address */
static inline int parse_ether_addr(struct ether_addr *hwaddr, const char *str)
{
	/* 01 34 67 90 23 56 */
	/* XX:XX:XX:XX:XX:XX */
	if (strlen(str) != 17 ||
			!isxdigit(str[0]) ||
			!isxdigit(str[1]) ||
			str[2] != ':' ||
			!isxdigit(str[3]) ||
			!isxdigit(str[4]) ||
			str[5] != ':' ||
			!isxdigit(str[6]) ||
			!isxdigit(str[7]) ||
			str[8] != ':' ||
			!isxdigit(str[9]) ||
			!isxdigit(str[10]) ||
			str[11] != ':' ||
			!isxdigit(str[12]) ||
			!isxdigit(str[13]) ||
			str[14] != ':' ||
			!isxdigit(str[15]) ||
			!isxdigit(str[16])) {
		printf("invalid mac hardware address format->%s<-\n", str);
		return 0;
	}
	sscanf(str, "%02zx:%02zx:%02zx:%02zx:%02zx:%02zx",
			(size_t *) &hwaddr->addr_bytes[0],
			(size_t *) &hwaddr->addr_bytes[1],
			(size_t *) &hwaddr->addr_bytes[2],
			(size_t *) &hwaddr->addr_bytes[3],
			(size_t *) &hwaddr->addr_bytes[4],
			(size_t *) &hwaddr->addr_bytes[5]);
	return 1;
}

static inline void set_unused_lcore(int *core, uint64_t *used_coremask)
{
	if (*core != -1) {
		if (!rte_lcore_is_enabled(*core))
			rte_panic("Invalid Core Assignment - "
					"core %u not in coremask", *core);
		return;
	}
	unsigned lcore;
	RTE_LCORE_FOREACH(lcore) {
		if ((1ULL << lcore) & *used_coremask)
			continue;
		*used_coremask |= (1ULL << lcore);
		*core = lcore;
		return;
	}
	rte_panic("No free core available - check coremask");
}

/**
 * Function to parse command line config.
 *
 * @param app
 *	global app config structure.
 * @param argc
 *	number of arguments.
 * @param argv
 *	list of arguments.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static inline int
parse_config_args(struct app_params *app, int argc, char **argv)
{
	int opt;
	int option_index;
	int i;
	struct ether_addr mac_addr;
	uint32_t ipv4_addr;
	uint64_t used_coremask = 0;

	static struct option spgw_opts[] = {
		{"s1u_ip", required_argument, 0, 'i'},
		{"sgi_ip", required_argument, 0, 's'},
		{"s1u_mac", required_argument, 0, 'm'},
		{"sgi_mac", required_argument, 0, 'n'},
		{"s1uc", required_argument, 0, 'u'},
		{"sgic", required_argument, 0, 'g'},
		{"bal", required_argument, 0, 'b'},
		{"mct", required_argument, 0, 'c'},
		{"spns_dns", required_argument, 0, 'p'},
		{"num_workers", required_argument, 0, 'w'},
		{"iface", required_argument, 0, 'd'},
		{"stats", required_argument, 0, 't'},
		{"log", required_argument, 0, 'l'},
		{NULL, 0, 0, 0}
	};

	optind = 0;		/* reset getopt lib */

	while ((opt = getopt_long(argc, argv, "i:s:m:n:u:g:b:m:w:d",
					spgw_opts, &option_index)) != EOF) {
		switch (opt) {
		/* s1u_ip address */
		case 'i':
			if (!inet_aton(optarg, (struct in_addr *)&app->s1u_ip)) {
				printf("Invalid s1u interface ip ->%s<-\n",
						optarg);
				dp_print_usage();
				app->s1u_ip = 0;
				return -1;
			}
			printf("Parsed s1u ip: %s\n",
				inet_ntoa(*((struct in_addr *)&app->s1u_ip)));
			break;

			/* sgi_ip address */
		case 's':
			if (!inet_aton(optarg, (struct in_addr *)&app->sgi_ip)) {
				printf("invalid sgi interface ip ->%s<-\n",
						optarg);
				dp_print_usage();
				app->sgi_ip = 0;
				return -1;
			}
			printf("Parsed sgi ip: %s\n",
				inet_ntoa(*((struct in_addr *)&app->sgi_ip)));
			break;

			/* s1u_mac address */
		case 'm':
			if (!parse_ether_addr(&app->s1u_ether_addr, optarg)) {
				dp_print_usage();
				return -1;
			}
			printf("Parsed s1u mac\n");
			for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
				rte_eth_macaddr_get(i, &mac_addr);
				if (is_same_ether_addr
					(&app->s1u_ether_addr, &mac_addr)) {
					printf("s1u port %d\n", i);
					app->s1u_port = i;
					break;
				}
			}
			break;

			/* sgi_mac address */
		case 'n':
			if (!parse_ether_addr(&app->sgi_ether_addr, optarg)) {
				dp_print_usage();
				return -1;
			}
			printf("Parsed sgi mac\n");
			for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
				rte_eth_macaddr_get(i, &mac_addr);
				if (is_same_ether_addr
					(&app->sgi_ether_addr, &mac_addr)) {
					printf("sgi port %d\n", i);
					app->sgi_port = i;
					break;
				}
			}
			break;

			/* enb_mac address */
		case 'e':
			if (!parse_ether_addr(&app->enb_ether_addr, optarg)) {
				dp_print_usage();
				return -1;
			}
			break;

			/* as_mac address */
		case 'a':
			if (!parse_ether_addr(&app->as_ether_addr, optarg)) {
				dp_print_usage();
				return -1;
			}
			break;

		case 'l':
			app->log_level = atoi(optarg);
			break;

		case 'u':
			epc_app.core_rx[S1U_PORT_ID] = atoi(optarg);
			epc_app.core_tx[S1U_PORT_ID] = atoi(optarg);
			printf("Parsed core_s1u:\t%d\n",
						epc_app.core_rx[S1U_PORT_ID]);
			used_coremask |= (1ULL << epc_app.core_rx[S1U_PORT_ID]);
			break;

		case 'g':
			epc_app.core_rx[SGI_PORT_ID] = atoi(optarg);
			epc_app.core_tx[SGI_PORT_ID] = atoi(optarg);
			printf("Parsed core_sgi:\t%d\n",
						epc_app.core_rx[SGI_PORT_ID]);
			used_coremask |= (1ULL << epc_app.core_rx[SGI_PORT_ID]);
			break;

		case 'b':
			epc_app.core_load_balance = atoi(optarg);
			printf("Parsed core_load_balance:\t%d\n",
						epc_app.core_load_balance);
			used_coremask |= (1ULL << epc_app.core_load_balance);
			break;

		case 'c':
			epc_app.core_mct = atoi(optarg);
			printf("Parsed core_mct:\t%d\n", epc_app.core_mct);
			used_coremask |= (1ULL << epc_app.core_mct);
			break;

		case 'p':
			epc_app.core_spns_dns = atoi(optarg);
			printf("Parsed core_spns_dns:\t%d\n", epc_app.core_spns_dns);
			used_coremask |= (1ULL << epc_app.core_spns_dns);
			break;

		case 'w':
			epc_app.num_workers = atoi(optarg);
			printf("Parsed num_workers:\t%d\n",
						epc_app.num_workers);
			break;

		case 'd':
			epc_app.core_iface = atoi(optarg);
			printf("Parsed core_iface:\t%d\n", epc_app.core_iface);
			used_coremask |= (1ULL << epc_app.core_iface);
			break;

		case 't':
			epc_app.core_stats = atoi(optarg);
			printf("Parsed core_stats:\t%d\n", epc_app.core_stats);
#ifdef STATS
			used_coremask |= (1ULL << epc_app.core_stats);
#else
			printf("DP compiled without STATS flag in Makefile."
				" Ignoring stats core assignment");
#endif
			break;

		default:
			dp_print_usage();
			return -1;
		}		/* end switch (opt) */
	}			/* end while() */

	set_unused_lcore(&epc_app.core_rx[S1U_PORT_ID], &used_coremask);
	epc_app.core_tx[S1U_PORT_ID] = epc_app.core_rx[S1U_PORT_ID];
	set_unused_lcore(&epc_app.core_rx[SGI_PORT_ID], &used_coremask);
	epc_app.core_tx[SGI_PORT_ID] = epc_app.core_rx[SGI_PORT_ID];
	set_unused_lcore(&epc_app.core_load_balance, &used_coremask);
	set_unused_lcore(&epc_app.core_mct, &used_coremask);
	set_unused_lcore(&epc_app.core_iface, &used_coremask);
#ifdef STATS
	set_unused_lcore(&epc_app.core_stats, &used_coremask);
#endif
	set_unused_lcore(&epc_app.core_spns_dns, &used_coremask);
	for (i = 0; i < epc_app.num_workers; ++i) {
		epc_app.worker_cores[i] = -1;
		set_unused_lcore(&epc_app.worker_cores[i], &used_coremask);
	}
	return 0;
}

/**
 * Function to initialize the dp config.
 *
 * @param argc
 *	number of arguments.
 * @param argv
 *	list of arguments.
 *
 * @return
 *	None
 */
void dp_init(int argc, char **argv)
{
	if (parse_config_args(&app, argc, argv) < 0)
		rte_exit(EXIT_FAILURE, "Error: Config parse fail !!!\n");
}
