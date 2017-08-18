/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
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
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_lcore.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_table_lpm.h>
#include <rte_table_hash.h>
#include <rte_pipeline.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_port_ring.h>
#include <rte_table_stub.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_errno.h>

#include "epc_arp_icmp.h"
#include "epc_packet_framework.h"
#include "util.h"
#include "cdr.h"
#include "main.h"


#if (RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN)
/* x86 == little endian
 * network  == big endian
 */
#define CHECK_ENDIAN_16(x) rte_be_to_cpu_16(x)
#define CHECK_ENDIAN_32(x) rte_be_to_cpu_32(x)
#else
#define CHECK_ENDIAN_16(x) (x)
#define CHECK_ENDIAN_32(x) (x)
#endif
/**
 * no. of mbuf.
 */
#define NB_ARPICMP_MBUF  256
/**
 * ipv4 version
 */
#define IP_VERSION_4 0x40
/**
 * default IP header length == five 32-bits words.
 */
#define IP_HDRLEN  0x05
/**
 * header def.
 */
#define IP_VHL_DEF (IP_VERSION_4 | IP_HDRLEN)
/**
 * check multicast ipv4 address.
 */
#define is_multicast_ipv4_addr(ipv4_addr) \
	(((rte_be_to_cpu_32((ipv4_addr)) >> 24) & 0x000000FF) == 0xE0)
/**
 * pipeline port out action handler
 */
#define PIPELINE_PORT_OUT_AH(f_ah, f_pkt_work, f_pkt4_work) \
static int							\
f_ah(                    			\
		struct rte_mbuf *pkt,		\
		uint64_t *pkts_mask,		\
		void *arg)					\
{									\
	f_pkt4_work(pkt, arg);			\
	f_pkt_work(pkt, arg);			\
	int i = *pkts_mask; i++;		\
	return 0;						\
}
/**
 * pipeline port out bulk action handler
 */
#define PIPELINE_PORT_OUT_BAH(f_ah, f_pkt_work, f_pkt4_work)	\
static int							\
f_ah(								\
		struct rte_mbuf **pkt,		\
		uint64_t *pkts_mask,		\
		void *arg)					\
{									\
	f_pkt4_work(*pkt, arg);			\
	f_pkt_work(*pkt, arg);			\
	int i = *pkts_mask; i++;		\
	return 0;						\
}

/**
 * unused.
 */
uint32_t arp_icmp_get_mac_req;
uint32_t arp_icmp_nh_found;
uint32_t arp_icmp_no_nh_found;
uint32_t arp_icmp_arp_entry_found;
uint32_t arp_icmp_no_arp_entry_found;
uint32_t arp_route_tbl_index;

/**
 * print arp table
 */
static void print_arp_table(void);
/**
 * memory pool for arp pkts.
 */
struct rte_mempool *arp_icmp_pktmbuf_tx_pool;
/**
 * memory pool for queued up user pkts.
 */
struct rte_mempool *arp_queued_pktmbuf_tx_pool;
/**
 * arp pkts buffer.
 */
struct rte_mbuf *arp_icmp_pkt;
/**
 * hash params.
 */
static struct rte_hash_parameters arp_hash_params = {
	.name = "ARP",
	.entries = 64*64,
	.reserved = 0,
	.key_len = sizeof(struct pipeline_arp_icmp_arp_key_ipv4),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
};
/**
 * rte hash handler.
 */
struct rte_hash *arp_hash_handle;
/**
 * handler lock.
 */
rte_rwlock_t arp_hash_handle_lock;
/**
 * arp pipeline
 */
struct rte_pipeline *myP;
/**
 * arp port address
 */
struct arp_port_address {
	/** ipv4 address*/
	uint32_t ip;
	/** mac address */
	struct ether_addr *mac_addr;
};
/**
 * ports mac address.
 */
extern struct ether_addr ports_eth_addr[];
/**
 * arp port address
 */
static struct arp_port_address arp_port_addresses[RTE_MAX_ETHPORTS];
/**
 * arp params structure.
 */
struct epc_arp_icmp_params {
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
	/** table id */
	uint32_t table_id;
	/** RTE pipeline */
	struct rte_pipeline *p;
	/** RTE pipeline name*/
	char   name[PIPE_NAME_SIZE];
} __rte_cache_aligned;
/**
 * global arp param variable.
 */
static struct epc_arp_icmp_params ai_params;

uint32_t pkt_hit_count;
uint32_t pkt_miss_count;
uint32_t pkt_key_count;
uint32_t pkt_out_count;

struct arp_icmp_route_table_entry {
	uint32_t ip;
	uint32_t mask;
	uint32_t port;
	uint32_t nh;
};

struct ether_addr broadcast_ether_addr = {
	.addr_bytes[0] = 0xFF,
	.addr_bytes[1] = 0xFF,
	.addr_bytes[2] = 0xFF,
	.addr_bytes[3] = 0xFF,
	.addr_bytes[4] = 0xFF,
	.addr_bytes[5] = 0xFF,
};
static const struct ether_addr null_ether_addr = {
	.addr_bytes[0] = 0x00,
	.addr_bytes[1] = 0x00,
	.addr_bytes[2] = 0x00,
	.addr_bytes[3] = 0x00,
	.addr_bytes[4] = 0x00,
	.addr_bytes[5] = 0x00,
};

static void print_ip(int ip)
{
	unsigned char bytes[4];
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
	printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
}
/**
 * Add entry in ARP table.
 *
 * @param arp_key
 *	key.
 * @param ret_arp_data
 *	return arp entry from table.
 *
 */
static int add_arp_data(struct pipeline_arp_icmp_arp_key_ipv4 *arp_key,
		struct arp_entry_data *ret_arp_data) {
	int ret;
	struct arp_entry_data *tmp_arp_data = NULL;
	rte_rwlock_write_lock(&arp_hash_handle_lock);
	/* Check for value while locked */
	ret = rte_hash_lookup_data(arp_hash_handle, arp_key, (void **)&tmp_arp_data);

	if (ret == -ENOENT) {
		/* entry not yet added, do so now */
		ret = rte_hash_add_key_data(arp_hash_handle, arp_key, ret_arp_data);
		if (ret) {
			/* We panic here because either:
			 * ret == -EINVAL and a parameter got messed up, or
			 * ret == -ENOSPC and the hash table isn't big enough
			 */
			rte_panic("ARP: Error on entry add for %s - %s",
					inet_ntoa(*(struct in_addr *)&arp_key->ip),
					rte_strerror(abs(ret)));
		}
	} else if (ret < 0) {
		/* We panic here because ret == -EINVAL and a parameter got
		 * messed up, or dpdk hash lib changed and this needs corrected */
		rte_panic("ARP: Error on entry add for %s - %s",
				inet_ntoa(*(struct in_addr *)&arp_key->ip),
				rte_strerror(abs(ret)));
	} else {
		/* entry already exists */
		ret = EEXIST;
	}

	rte_rwlock_write_unlock(&arp_hash_handle_lock);
	return ret;
}


/**
 * returns 0 if packet was queued
 * return 1 if arp was resolved prior to acquiring lock - not queued - to be forwarded
 * return -1 if packet could not be queued - no ring
 */
int arp_queue_unresolved_packet(struct arp_entry_data *arp_data, struct rte_mbuf *m)
{
	int ret;
	struct rte_mbuf *buf_pkt = rte_pktmbuf_clone(m, arp_queued_pktmbuf_tx_pool);

	struct epc_meta_data *from_meta_data;
	struct epc_meta_data *to_meta_data;

	if (buf_pkt == NULL) {
		/* Double check resolution of IP */
		if (arp_data->status == COMPLETE) {
			return 1;
		} else {
			RTE_LOG(NOTICE, DP, "ARP: Unable to clone pkt for %s buffer- Dropping\n",
					inet_ntoa(*(struct in_addr *)&arp_data->ip));
			print_arp_table();
			return -1;
		}
	}

	from_meta_data =
		(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(m, META_DATA_OFFSET);
	to_meta_data =
		(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(buf_pkt, META_DATA_OFFSET);
	*to_meta_data = *from_meta_data;

	rte_rwlock_write_lock(&arp_data->queue_lock);
	if (arp_data->queue == NULL) {
		rte_rwlock_write_unlock(&arp_data->queue_lock);
		if (arp_data->status == COMPLETE) {
			/* Address resolved while waiting for lock */
			rte_pktmbuf_free(buf_pkt);
			return 1;
		} else {
			RTE_LOG(NOTICE, DP, "ARP: No %s buffer exists for pkt - Dropping\n",
					inet_ntoa(*(struct in_addr *)&arp_data->ip));
			print_arp_table();
			return -1;
		}
	}

	ret = rte_ring_enqueue(arp_data->queue, buf_pkt);
	if (ret == -ENOBUFS) {
		struct rte_mbuf *tmp = NULL;
		ret = rte_ring_dequeue(arp_data->queue, (void **)&tmp);
		if (ret) {
			rte_pktmbuf_free(buf_pkt);
			printf("Can't queue packet destined for %s, dropping pkt\n",
					inet_ntoa(*(struct in_addr *) &arp_data->ip));
		} else {
			rte_pktmbuf_free(tmp);
			rte_ring_enqueue(arp_data->queue, (void **)buf_pkt);
			if (ARPICMP_DEBUG)
				printf("Ring full for %s, dropping oldest pkt\n",
						inet_ntoa(*(struct in_addr *) &arp_data->ip));
		}
	} else if (ret) {
		rte_pktmbuf_free(buf_pkt);
		printf("Unable to queue packet for %s - %s (%d)\n",
				inet_ntoa(*(struct in_addr *) &arp_data->ip),
				rte_strerror(abs(ret)), ret);
	} else {
		if (ARPICMP_DEBUG) {
			printf("                               Queued packet for %20s\n",
					inet_ntoa(*(struct in_addr *) &arp_data->ip));
		}
	}
	rte_rwlock_write_unlock(&arp_data->queue_lock);

	return 0;
}

static const char *
arp_op_name(uint16_t arp_op)
{
	switch (CHECK_ENDIAN_16(arp_op)) {
	case (ARP_OP_REQUEST):
		return "ARP Request";
	case (ARP_OP_REPLY):
		return "ARP Reply";
	case (ARP_OP_REVREQUEST):
		return "Reverse ARP Request";
	case (ARP_OP_REVREPLY):
		return "Reverse ARP Reply";
	case (ARP_OP_INVREQUEST):
		return "Peer Identify Request";
	case (ARP_OP_INVREPLY):
		return "Peer Identify Reply";
	default:
		break;
	}
	return "Unkwown ARP op";
}

static void
print_icmp_packet(struct icmp_hdr *icmp_h)
{
	printf("  ICMP: type=%d (%s) code=%d id=%d seqnum=%d\n",
			icmp_h->icmp_type,
			(icmp_h->icmp_type == IP_ICMP_ECHO_REPLY ? "Reply" :
			 (icmp_h->icmp_type == IP_ICMP_ECHO_REQUEST ? "Reqest" : "Undef")),
			icmp_h->icmp_code,
			CHECK_ENDIAN_16(icmp_h->icmp_ident),
			CHECK_ENDIAN_16(icmp_h->icmp_seq_nb));
}

static void
print_ipv4_h(struct ipv4_hdr *ip_h)
{
	struct icmp_hdr *icmp_h = (struct icmp_hdr *)((char *)ip_h + sizeof(struct ipv4_hdr));
	printf("  IPv4: Version=%d HLEN=%d Type=%d Length=%d\n",
			(ip_h->version_ihl & 0xf0) >> 4,
			(ip_h->version_ihl & 0x0f),
			ip_h->type_of_service,
			rte_cpu_to_be_16(ip_h->total_length));
	printf("Dst IP:");
	print_ip(ntohl(ip_h->dst_addr));
	printf("Src IP:");
	print_ip(ntohl(ip_h->src_addr));

	if (ip_h->next_proto_id == IPPROTO_ICMP) {
		print_icmp_packet(icmp_h);
	}
}


static void
print_arp_packet(struct arp_hdr *arp_h)
{
	printf("  ARP:  hrd=%d proto=0x%04x hln=%d "
			"pln=%d op=%u (%s)\n",
			CHECK_ENDIAN_16(arp_h->arp_hrd),
			CHECK_ENDIAN_16(arp_h->arp_pro), arp_h->arp_hln,
			arp_h->arp_pln, CHECK_ENDIAN_16(arp_h->arp_op),
			arp_op_name(arp_h->arp_op));

	if (CHECK_ENDIAN_16(arp_h->arp_hrd) != ARP_HRD_ETHER) {
		printf("incorrect arp_hrd format for IPv4 ARP (%d)\n", (arp_h->arp_hrd));
	} else if (CHECK_ENDIAN_16(arp_h->arp_pro) != ETHER_TYPE_IPv4) {
		printf("incorrect arp_pro format for IPv4 ARP (%d)\n", (arp_h->arp_pro));
	} else if (arp_h->arp_hln != 6) {
		printf("incorrect arp_hln format for IPv4 ARP (%d)\n", arp_h->arp_hln);
	} else if (arp_h->arp_pln != 4) {
		printf("incorrect arp_pln format for IPv4 ARP (%d)\n", arp_h->arp_pln);
	} else {
		printf("  sha=%02X:%02X:%02X:%02X:%02X:%02X",
				arp_h->arp_data.arp_sha.addr_bytes[0],
				arp_h->arp_data.arp_sha.addr_bytes[1],
				arp_h->arp_data.arp_sha.addr_bytes[2],
				arp_h->arp_data.arp_sha.addr_bytes[3],
				arp_h->arp_data.arp_sha.addr_bytes[4],
				arp_h->arp_data.arp_sha.addr_bytes[5]);
		printf(" sip=%d.%d.%d.%d\n",
				(CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) >> 24) & 0xFF,
				(CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) >> 16) & 0xFF,
				(CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) >>  8) & 0xFF,
				CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) & 0xFF);
		printf("  tha=%02X:%02X:%02X:%02X:%02X:%02X",
				arp_h->arp_data.arp_tha.addr_bytes[0],
				arp_h->arp_data.arp_tha.addr_bytes[1],
				arp_h->arp_data.arp_tha.addr_bytes[2],
				arp_h->arp_data.arp_tha.addr_bytes[3],
				arp_h->arp_data.arp_tha.addr_bytes[4],
				arp_h->arp_data.arp_tha.addr_bytes[5]);
		printf(" tip=%d.%d.%d.%d\n",
				(CHECK_ENDIAN_32(arp_h->arp_data.arp_tip) >> 24) & 0xFF,
				(CHECK_ENDIAN_32(arp_h->arp_data.arp_tip) >> 16) & 0xFF,
				(CHECK_ENDIAN_32(arp_h->arp_data.arp_tip) >>  8) & 0xFF,
				CHECK_ENDIAN_32(arp_h->arp_data.arp_tip) & 0xFF);
	}
}

static void
print_eth(struct ether_hdr *eth_h)
{
	printf("  ETH:  src=%02X:%02X:%02X:%02X:%02X:%02X",
			eth_h->s_addr.addr_bytes[0],
			eth_h->s_addr.addr_bytes[1],
			eth_h->s_addr.addr_bytes[2],
			eth_h->s_addr.addr_bytes[3],
			eth_h->s_addr.addr_bytes[4],
			eth_h->s_addr.addr_bytes[5]);
	printf(" dst=%02X:%02X:%02X:%02X:%02X:%02X\n",
			eth_h->d_addr.addr_bytes[0],
			eth_h->d_addr.addr_bytes[1],
			eth_h->d_addr.addr_bytes[2],
			eth_h->d_addr.addr_bytes[3],
			eth_h->d_addr.addr_bytes[4],
			eth_h->d_addr.addr_bytes[5]);

}

static void
print_mbuf(const char *rx_tx, unsigned portid, struct rte_mbuf *mbuf, unsigned line)
{
	struct ether_hdr *eth_h = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	struct arp_hdr *arp_h = (struct arp_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	struct ipv4_hdr *ipv4_h = (struct ipv4_hdr *)((char *)eth_h + sizeof(struct ether_hdr));

	printf("%s(%d): on port %d pkt-len=%u nb-segs=%u\n",
			rx_tx, line, portid, mbuf->pkt_len, mbuf->nb_segs);
	print_eth(eth_h);
	switch (rte_cpu_to_be_16(eth_h->ether_type)) {
	case ETHER_TYPE_IPv4:
		print_ipv4_h(ipv4_h);
		break;
	case ETHER_TYPE_ARP:
		print_arp_packet(arp_h);
		break;
	default:
		printf("  unknown packet type\n");
		break;
	}
	fflush(stdout);
}

struct arp_entry_data *
retrieve_arp_entry(struct pipeline_arp_icmp_arp_key_ipv4 arp_key)
{
	int ret;
	struct arp_entry_data *ret_arp_data = NULL;
	arp_key.filler1 = 0;
	arp_key.filler2 = 0;
	arp_key.filler3 = 0;
	if (ARPICMP_DEBUG)
		printf(" Enter retrieve_arp_entry...lookup for 0x%x\n", arp_key.ip);

	while (1) {
		/* We have to keep trying to prevent race condition:
		 * multiple threads each creating arp_data for same ip */
		ret = rte_hash_lookup_data(arp_hash_handle, &arp_key, (void **)&ret_arp_data);
		if (ret < 0) {
			/* create a arp_entry */
			ret_arp_data = rte_malloc_socket(NULL, sizeof(struct arp_entry_data),
					RTE_CACHE_LINE_SIZE, rte_socket_id());
			ret_arp_data->last_update = time(NULL);
			ret_arp_data->status = INCOMPLETE;
			rte_rwlock_init(&ret_arp_data->queue_lock);
			rte_rwlock_write_lock(&ret_arp_data->queue_lock);

			/* attempt to add arp_entry to hash */
			ret = add_arp_data(&arp_key, ret_arp_data);

			if (ret == EEXIST) {
				rte_rwlock_write_unlock(&ret_arp_data->queue_lock);
				rte_free(ret_arp_data);
				/* Some other thread has 'beat' this thread in creation of arp_data, try again */
				continue;
			}

			/* This thread 'beat' every other in the creation of arp_data for this ip */
			ret_arp_data->port = arp_key.port_id;
			ret_arp_data->ip = arp_key.ip;
			ret_arp_data->queue = rte_ring_create(
					inet_ntoa(*((struct in_addr *)&arp_key.ip)),
					ARP_BUFFER_RING_SIZE,
					rte_socket_id(),
					RING_F_SP_ENQ | RING_F_SC_DEQ);

			if (ret_arp_data->queue == NULL) {
				printf("Error creating arp ring for %s on port %d - %s (%d)\n",
						inet_ntoa(*(struct in_addr *)&arp_key.ip), arp_key.port_id,
						rte_strerror(abs(rte_errno)), rte_errno);
				print_arp_table();
				if (rte_errno == EEXIST) {
					rte_rwlock_write_unlock(&ret_arp_data->queue_lock);
					rte_free(ret_arp_data);
					/* Some other thread has 'beat' this thread in creation of arp_data, try again */
					continue;
				}
			}
			send_arp_req(arp_key.port_id, arp_key.ip);
			rte_rwlock_write_unlock(&ret_arp_data->queue_lock);

		} else {
			/* arp_entry has already been created for this ip */
			if (ARPICMP_DEBUG)
				printf("ARP entry found for ip 0x%x\n", arp_key.ip);
			/* add INCOMPLETE arp entry */
			if (ARPICMP_DEBUG)
				printf(" Exit retrieve_arp_entry...\n");
			if (ret_arp_data->status == INCOMPLETE) {
				time_t now = time(NULL);
				if (now - ret_arp_data->last_update >= ARP_TIMEOUT) {
					ret_arp_data->last_update = now;
					send_arp_req(arp_key.port_id, arp_key.ip);
				}
			}
			break;
		}
	}

	return ret_arp_data;
}

void
print_arp_table(void)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;
	printf("\tport  hw addr              status    ip addr\n");

	while (rte_hash_iterate(arp_hash_handle, &next_key, &next_data, &iter) >= 0) {

		struct arp_entry_data *tmp_arp_data = (struct arp_entry_data *)next_data;
		struct pipeline_arp_icmp_arp_key_ipv4 tmp_arp_key;

		memcpy(&tmp_arp_key, next_key, sizeof(struct pipeline_arp_icmp_arp_key_ipv4));
		printf("\t%4d  %02X:%02X:%02X:%02X:%02X:%02X  %10s  %s\n",
				tmp_arp_data->port,
				tmp_arp_data->eth_addr.addr_bytes[0],
				tmp_arp_data->eth_addr.addr_bytes[1],
				tmp_arp_data->eth_addr.addr_bytes[2],
				tmp_arp_data->eth_addr.addr_bytes[3],
				tmp_arp_data->eth_addr.addr_bytes[4],
				tmp_arp_data->eth_addr.addr_bytes[5],
				tmp_arp_data->status == COMPLETE ? "COMPLETE" : "INCOMPLETE",
				inet_ntoa(*((struct in_addr *)(&tmp_arp_data->ip))));
	}
}

static void
arp_send_buffered_pkts(struct rte_ring *queue, const struct ether_addr *hw_addr, uint8_t portid)
{
	struct adc_rules *adc_rule = NULL;
	struct ipv4_hdr *ip_h;
	struct dp_session_info *session;

	unsigned ring_count = rte_ring_count(queue);
	unsigned count = 0;

	while (!rte_ring_empty(queue)) {
		struct rte_mbuf *pkt;
		int ret = rte_ring_dequeue(queue, (void **) &pkt);
		if (ret == 0) {
			struct ether_hdr *e_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
			ether_addr_copy(hw_addr, &e_hdr->d_addr);
			ether_addr_copy(&ports_eth_addr[portid], &e_hdr->s_addr);
			rte_pipeline_port_out_packet_insert(myP, portid, pkt);
			++count;

		}
	}

	if (ARPICMP_DEBUG) {
		printf("forwarding %u/%u packets queued for ARP\n", count, ring_count);
	}

	rte_ring_free(queue);
	queue = NULL;
}

static void
populate_arp_entry(const struct ether_addr *hw_addr, uint32_t ipaddr, uint8_t portid)
{
	int ret;
	struct pipeline_arp_icmp_arp_key_ipv4 arp_key;
	arp_key.port_id = portid;
	arp_key.ip = ipaddr;
	arp_key.filler1 = 0;
	arp_key.filler2 = 0;
	arp_key.filler3 = 0;

	if (ARPICMP_DEBUG)
		printf("populate_arp_entry ip%x, port %d\n", arp_key.ip, arp_key.port_id);

	while (1) {
		struct arp_entry_data *arp_data = retrieve_arp_entry(arp_key);
		if (arp_data) {
			arp_data->last_update = time(NULL);
			if (is_same_ether_addr(&arp_data->eth_addr, hw_addr)) {
				if (ARPICMP_DEBUG)
					printf("arp_entry exists ip%x, port %d\n", arp_key.ip, arp_key.port_id);
				return;
			} else {
				ether_addr_copy(hw_addr, &arp_data->eth_addr);
				if (arp_data->status == INCOMPLETE) {
					if (arp_data->queue) {
						rte_rwlock_write_lock(&arp_data->queue_lock);
						arp_send_buffered_pkts(arp_data->queue, hw_addr, portid);
						rte_rwlock_write_unlock(&arp_data->queue_lock);
					}
					arp_data->status = COMPLETE;
				}
			}
			return;
		} else {
			arp_data = rte_malloc_socket(NULL, sizeof(struct arp_entry_data), RTE_CACHE_LINE_SIZE, rte_socket_id());
			ether_addr_copy(hw_addr, &arp_data->eth_addr);
			arp_data->status = COMPLETE;
			arp_data->port = portid;
			arp_data->ip = ipaddr;
			arp_data->queue = NULL;
			ret = add_arp_data(&arp_key, arp_data);

			if (ret) {
				/* Some other thread created an entry for this ip */
				rte_free(arp_data);
				continue;
			}
			return;
		}
	}
}

void print_pkt1(struct rte_mbuf *pkt)
{
	if (ARPICMP_DEBUG < 2)
		return;
	uint8_t *rd = RTE_MBUF_METADATA_UINT8_PTR(pkt, 0);
	int i = 0, j = 0;
	printf("ARPICMP Packet Stats - hit = %u, miss = %u, key %u, out %u\n", pkt_hit_count, pkt_miss_count, pkt_key_count, pkt_out_count);
	for (i = 0; i < 20; i++) {
		for (j = 0; j < 20; j++)
			printf("%02x ", rd[(20*i)+j]);
		printf("\n");
	}
}

static void
get_mac_ip_addr(struct arp_port_address *addr, uint8_t port_id)
{
	if (app.s1u_port == port_id) {
		addr[port_id].ip = app.s1u_ip;
		addr[port_id].mac_addr = &app.s1u_ether_addr;
	} else if (app.sgi_port == port_id) {
		addr[port_id].ip = app.sgi_ip;
		addr[port_id].mac_addr = &app.sgi_ether_addr;
	} else {
		printf("Unknown input port\n");
	}
}

int
send_arp_req(unsigned port_id, uint32_t ip)
{
	struct ether_hdr *eth_h;
	struct arp_hdr *arp_h;

	struct rte_mbuf *arp_pkt = rte_pktmbuf_alloc(arp_icmp_pktmbuf_tx_pool);
	if (arp_pkt == NULL) {
		printf("Error allocating arp_pkt rte_mbuf\n");
		return -1;
	}

	eth_h = rte_pktmbuf_mtod(arp_pkt, struct ether_hdr *);

	ether_addr_copy(&broadcast_ether_addr, &eth_h->d_addr);
	ether_addr_copy(arp_port_addresses[port_id].mac_addr, &eth_h->s_addr);
	eth_h->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);

	arp_h = (struct arp_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	arp_h->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
	arp_h->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	arp_h->arp_hln = ETHER_ADDR_LEN;
	arp_h->arp_pln = sizeof(uint32_t);
	arp_h->arp_op = rte_cpu_to_be_16(ARP_OP_REQUEST);

	ether_addr_copy(arp_port_addresses[port_id].mac_addr, &arp_h->arp_data.arp_sha);
	arp_h->arp_data.arp_sip = arp_port_addresses[port_id].ip;
	ether_addr_copy(&null_ether_addr, &arp_h->arp_data.arp_tha);
	arp_h->arp_data.arp_tip = ip;
	arp_pkt->pkt_len  = 42;
	arp_pkt->data_len = 42;


	if (ARPICMP_DEBUG) {
		printf("Sending arp request from %20s to ", inet_ntoa(*(struct in_addr *) &arp_h->arp_data.arp_sip));
		printf("%20s\n", inet_ntoa(*(struct in_addr *) &arp_h->arp_data.arp_tip));
	}
	if (ARPICMP_DEBUG) {
		print_mbuf("TX", port_id, arp_pkt, __LINE__);
	}

	rte_pipeline_port_out_packet_insert(myP, port_id, arp_pkt);
	return 0;
}


static inline void
pkt_work_arp_icmp_key(
		struct rte_mbuf *pkt,
		void *arg)
{
	uint8_t in_port_id = (uint8_t)(uintptr_t)arg;
	struct ether_hdr *eth_h;
	struct arp_hdr *arp_h;
	struct ipv4_hdr *ip_h;
	struct icmp_hdr *icmp_h;

	uint32_t cksum;
	uint32_t ip_addr;

	uint32_t req_tip;

	pkt_key_count++;
	print_pkt1(pkt);

	eth_h = rte_pktmbuf_mtod(pkt, struct ether_hdr *);

	if ((eth_h->d_addr.addr_bytes[0] == 0x01)
			&& (eth_h->d_addr.addr_bytes[1] == 0x80)
			&& (eth_h->d_addr.addr_bytes[2] == 0xc2))
		return ;

	if ((eth_h->d_addr.addr_bytes[0] == 0x01)
			&& (eth_h->d_addr.addr_bytes[1] == 0x00)
			&& (eth_h->d_addr.addr_bytes[2] == 0x0c))
		return ;

	if (ARPICMP_DEBUG)
		print_eth(eth_h);

	if (eth_h->ether_type == rte_cpu_to_be_16(ETHER_TYPE_ARP)) {
		arp_h = (struct arp_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
		if (ARPICMP_DEBUG)
			print_arp_packet(arp_h);

		if (CHECK_ENDIAN_16(arp_h->arp_hrd) != ARP_HRD_ETHER)
			printf("Invalid hardware format of hardware address - not processing ARP req\n");
		else if (CHECK_ENDIAN_16(arp_h->arp_pro) != ETHER_TYPE_IPv4)
			printf("Invalid protocol address format - not processing ARP req\n");
		else if (arp_h->arp_hln != 6)
			printf("Invalid hardware address length - not processing ARP req\n");
		else if (arp_h->arp_pln != 4)
			printf("Invalid protocol address length - not processing ARP req\n");
		else {
			get_mac_ip_addr(arp_port_addresses, in_port_id);
			if (arp_h->arp_data.arp_tip != arp_port_addresses[in_port_id].ip) {
				if (ARPICMP_DEBUG) {
					printf("ARP requested IP address mismatches interface IP - discarding\n");
					printf("arp_tip = %s \n", inet_ntoa(*(struct in_addr *)&arp_h->arp_data.arp_tip));
					printf("arp_port_addresses = %s \n", inet_ntoa(*(struct in_addr *)&arp_port_addresses[in_port_id].ip));
					printf("in_port_id = %x \n", in_port_id);
				}
			} else if (arp_h->arp_op == rte_cpu_to_be_16(ARP_OP_REQUEST)) {
				/* revise conditionals to allow processing of requests with target ip = this ip and
				 * processing of replies to destination ip = this ip
				 */
				if (ARPICMP_DEBUG) {
					printf("arp_op %d, ARP_OP_REQUEST %d\n", arp_h->arp_op, rte_cpu_to_be_16(ARP_OP_REQUEST));
					print_mbuf("RX", in_port_id, pkt, __LINE__);
				}

				populate_arp_entry(&arp_h->arp_data.arp_sha, arp_h->arp_data.arp_sip, in_port_id);

				/* build reply */
				req_tip = arp_h->arp_data.arp_tip;
				ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);
				ether_addr_copy(arp_port_addresses[in_port_id].mac_addr, &eth_h->s_addr);
				arp_h->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
				ether_addr_copy(&eth_h->s_addr, &arp_h->arp_data.arp_sha);
				arp_h->arp_data.arp_tip = arp_h->arp_data.arp_sip;
				arp_h->arp_data.arp_sip = req_tip;
				ether_addr_copy(&eth_h->d_addr, &arp_h->arp_data.arp_tha);

				if (ARPICMP_DEBUG) {
					print_mbuf("TX", in_port_id, pkt, __LINE__);
					print_pkt1(pkt);
				}

				/* send packet */
				int pkt_size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct rte_mbuf));
				struct rte_mbuf *pkt1 = arp_icmp_pkt;
				if (pkt1) {
					memcpy(pkt1, pkt, pkt_size);
					rte_pipeline_port_out_packet_insert(myP, in_port_id, pkt1);
				}
			} else if (arp_h->arp_op == rte_cpu_to_be_16(ARP_OP_REPLY)) {
				/* TODO: Check if ARP request was actually sent!*/
				if (ARPICMP_DEBUG) {
					printf("ARP reply recieved for %s - "FORMAT_MAC"\n",
							inet_ntoa(*(struct in_addr *)&arp_h->arp_data.arp_sip),
							FORMAT_MAC_ARGS(arp_h->arp_data.arp_sha));
				}
				populate_arp_entry(&arp_h->arp_data.arp_sha, arp_h->arp_data.arp_sip, in_port_id);
			} else {
				if (ARPICMP_DEBUG)
					printf("Invalid ARP opcode - not processing ARP req %x\n", arp_h->arp_op);
			}
		}
	} else {
		ip_h = (struct ipv4_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
		icmp_h = (struct icmp_hdr *) ((char *)ip_h + sizeof(struct ipv4_hdr));
		if (ARPICMP_DEBUG)
			print_ipv4_h(ip_h);
		if (eth_h->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
			get_mac_ip_addr(arp_port_addresses, in_port_id);
			if (!is_same_ether_addr(arp_port_addresses[in_port_id].mac_addr,  &eth_h->d_addr)) {
				if (ARPICMP_DEBUG) {
					printf("Ethernet frame not destined for MAC address of received network interface - discarding\n");
				}
			} else if (ip_h->next_proto_id != IPPROTO_ICMP) {
				if (ARPICMP_DEBUG) {
					printf("IP protocol ID is not set to ICMP - discarding\n");
				}
			} else if ((ip_h->version_ihl & 0xf0) != IP_VERSION_4) {
				if (ARPICMP_DEBUG) {
					printf("IP version other than 4 - discarding\n");
				}
			} else if ((ip_h->version_ihl & 0x0f) != IP_HDRLEN) {
				if (ARPICMP_DEBUG) {
					printf("Unknown IHL - discarding\n");
				}
			} else {
				if (icmp_h->icmp_type == IP_ICMP_ECHO_REQUEST && icmp_h->icmp_code == 0) {
					if (ARPICMP_DEBUG)
						print_mbuf("RX", in_port_id, pkt, __LINE__);
					ip_addr = ip_h->src_addr;
					ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);
					ether_addr_copy(arp_port_addresses[in_port_id].mac_addr, &eth_h->s_addr);
					if (ip_h->dst_addr != arp_port_addresses[in_port_id].ip) {
						if (ARPICMP_DEBUG) {
							printf("IPv4 packet not destined for configured IP on RX port - discarding\n");
							printf("ip_h->dst_addr = %u, in_port_id = %u, arp_port_addresses.ip = %u\n",
									ip_h->dst_addr, in_port_id, arp_port_addresses[in_port_id].ip);
						}
					} else {
						if (is_multicast_ipv4_addr(ip_h->dst_addr)) {
							uint32_t ip_src;
							ip_src = ip_addr;
							if ((ip_src & 0x03000000) == 0x01000000)
								ip_src = (ip_src & 0xFCFFFFFF) | 0x02000000;
							else
								ip_src = (ip_src & 0xFCFFFFFF) | 0x01000000;
							ip_h->src_addr = ip_src;
							ip_h->dst_addr = ip_addr;

							ip_h->hdr_checksum = 0;
							ip_h->hdr_checksum = ~rte_raw_cksum(ip_h, sizeof(struct ipv4_hdr));
						} else {
							ip_h->src_addr = ip_h->dst_addr;
							ip_h->dst_addr = ip_addr;
						}
						icmp_h->icmp_type = IP_ICMP_ECHO_REPLY;
						cksum = ~icmp_h->icmp_cksum & 0xffff;
						cksum += ~htons(IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
						cksum += htons(IP_ICMP_ECHO_REPLY << 8);
						cksum = (cksum & 0xffff) + (cksum >> 16);
						cksum = (cksum & 0xffff) + (cksum >> 16);
						icmp_h->icmp_cksum = ~cksum;
						if (ARPICMP_DEBUG)
							print_mbuf("TX", in_port_id, pkt, __LINE__);

						/* send packet*/
						int pkt_size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct rte_mbuf));
						struct rte_mbuf *pkt1 = arp_icmp_pkt;
						if (pkt1) {
							if (ARPICMP_DEBUG)
								printf("Sending ping reply .... pkt_size %d\n", pkt_size);
							memcpy(pkt1, pkt, pkt_size);
							rte_pipeline_port_out_packet_insert(myP, in_port_id, pkt1);
						}  /* if (pkt1) */
					}  /* if (ip_h->dst_addr ...*/
				}  /* if (icmp_h->icmp_type == IP_ICMP_ECHO_REQUEST ...*/
			}  /* if (!is_same_ether_addr((struct ether_addr *) ...*/
		}  /* if (eth_h->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4))*/
	} /* if (eth_h->ether_type == rte_cpu_to_be_16(ETHER_TYPE_ARP))*/
}

static inline void
pkt4_work_arp_icmp_key(
		struct rte_mbuf **pkt,
		void *arg)
{
	(void)pkt;
	(void)arg;
	/* TO BE IMPLEMENTED IF REQUIRED */
}

static int port_in_ah_arp_icmp_key(struct rte_pipeline *p, struct rte_mbuf **pkts,
		uint32_t n,
		void *arg)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		if (pkts[i])
			pkt_work_arp_icmp_key(pkts[i], arg);
	}
	return 0;
}

void
epc_arp_icmp_init(void)
{
	struct rte_pipeline *p;
	uint32_t i, in_ports_arg_size;
	struct epc_arp_icmp_params *params = &ai_params;

	/* Pipeline */
	{
		struct rte_pipeline_params pipeline_params = {
			.name = "arp icmp",
			.socket_id = rte_socket_id(),
			.offset_port_id = 0,
		};

		p = rte_pipeline_create(&pipeline_params);
		if (p == NULL) {
			return;
		}

		myP = p;
	}

	/* Memory allocation for in_port_h_arg */
	in_ports_arg_size = RTE_CACHE_LINE_ROUNDUP((sizeof(struct pipeline_arp_icmp_in_port_h_arg)) * (NUM_SPGW_PORTS)); /* Fixme */
	struct pipeline_arp_icmp_in_port_h_arg *ap = rte_zmalloc_socket(NULL, in_ports_arg_size, RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (ap == NULL)
		return;

	/* Input ports */
	for (i = 0; i < epc_app.n_ports; i++) {
		struct rte_port_ring_reader_params port_ring_params = {
			.ring = epc_app.epc_mct_rx[i]
		};

		struct rte_pipeline_port_in_params port_params = {
			.ops = &rte_port_ring_reader_ops,
			.arg_create = &port_ring_params,
			.f_action = port_in_ah_arp_icmp_key,
			.arg_ah = (void *)(uintptr_t)i,
			.burst_size = epc_app.burst_size_tx_write
		};

		int status = rte_pipeline_port_in_create(p,
				&port_params,
				&params->port_in_id[i]);

		if (status) {
			rte_pipeline_free(p);
		}
		get_mac_ip_addr(arp_port_addresses, i);
	}

	/* Output ports */
	for (i = 0; i < epc_app.n_ports; i++) {
		struct rte_port_ring_writer_params port_ring_params = {
			.ring = epc_app.ring_tx[epc_app.core_mct][i],
			.tx_burst_sz = epc_app.burst_size_tx_write,
		};

		struct rte_pipeline_port_out_params port_params = {
			.ops = &rte_port_ring_writer_ops,
			.arg_create = (void *) &port_ring_params,
		};

		if (rte_pipeline_port_out_create(p, &port_params, &params->port_out_id[i])) {
			rte_panic("%s: Unable to configure output port for ring RX %i\n", __func__, i);
		}
	}

	struct rte_pipeline_table_params table_params = {
		.ops = &rte_table_stub_ops,
	};

	int status;

	status = rte_pipeline_table_create(p,
			&table_params,
			&params->table_id);

	if (status) {
		rte_pipeline_free(p);
		return;
	}

	/* Add entries to tables */
	for (i = 0; i < epc_app.n_ports; i++) {
		struct rte_pipeline_table_entry entry = {
			.action = RTE_PIPELINE_ACTION_DROP,
		};
		struct rte_pipeline_table_entry *default_entry_ptr;

		if (rte_pipeline_table_default_entry_add(p, params->table_id, &entry,
					&default_entry_ptr))
			rte_panic("Unable to add default entry to table %u\n",
					params->table_id);
	}


	for (i = 0; i < epc_app.n_ports; i++) {
		int status = rte_pipeline_port_in_connect_to_table(p,
				params->port_in_id[i],
				params->table_id);

		if (status) {
			rte_pipeline_free(p);
		}
	}

	for (i = 0; i < epc_app.n_ports; i++) {
		int status = rte_pipeline_port_in_enable(p,
				params->port_in_id[i]);

		if (status) {
			rte_pipeline_free(p);
		}
	}

	if (rte_pipeline_check(p) < 0) {
		rte_pipeline_free(p);
		rte_panic("%s: Pipeline consistency check failed\n", __func__);
	}

	/* create the arp_icmp mbuf rx pool */
	arp_icmp_pktmbuf_tx_pool = rte_pktmbuf_pool_create("arp_icmp_mbuf_tx_pool", NB_ARPICMP_MBUF, 32,
			0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	arp_queued_pktmbuf_tx_pool = rte_pktmbuf_pool_create("arp_queued_pktmbuf_tx_pool", NB_ARPICMP_MBUF, 32,
			0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (arp_icmp_pktmbuf_tx_pool == NULL) {
		return;
	}

	arp_icmp_pkt = rte_pktmbuf_alloc(arp_icmp_pktmbuf_tx_pool);
	if (arp_icmp_pkt == NULL) {
		return;
	}

	arp_hash_params.socket_id = rte_socket_id();
	arp_hash_handle = rte_hash_create(&arp_hash_params);
	if (!arp_hash_handle)
		rte_panic("%s hash create failed: %s (%u)\n.",
				arp_hash_params.name, rte_strerror(rte_errno),
				rte_errno);

	rte_rwlock_init(&arp_hash_handle_lock);
}

void epc_arp_icmp(__rte_unused void *arg)
{
	struct epc_arp_icmp_params *param = &ai_params;

	rte_pipeline_run(myP);
	if (++param->flush_count >= param->flush_max) {
		rte_pipeline_flush(myP);
		param->flush_count = 0;
	}
}
