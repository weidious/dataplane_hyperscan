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

#include <rte_cycles.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <arpa/inet.h>

#include "main.h"
#include "epc_packet_framework.h"
#include "gtpu.h"
#include "ipv4.h"
#include "udp.h"
#include "ether.h"
#include "util.h"
#include "meter.h"
#include <sponsdn.h>
#include <stdbool.h>
#include <offline_scanner.h>
extern uint64_t bear_stats[];
extern struct rte_hash *rte_adc_ue_hash;
extern uint64_t go;
void
gtpu_decap(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask)
{
	uint32_t i;
	int ret = 0;
	static uint64_t ul_num_dcap;
	struct ipv4_hdr *ipv4_hdr;
	struct udp_hdr *udp_hdr;
	struct gtpu_hdr *gtpu_hdr;
	struct epc_meta_data *meta_data;

	for (i = 0; i < n; i++) {
		/* reject if not with s1u ip */
		ipv4_hdr = get_mtoip(pkts[i]);
		if (ipv4_hdr->dst_addr != app.s1u_ip) {
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		/* reject un-tunneled packet */
		udp_hdr = get_mtoudp(pkts[i]);
		if (ntohs(udp_hdr->dst_port) != UDP_PORT_GTPU) {
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		gtpu_hdr = get_mtogtpu(pkts[i]);
		if (gtpu_hdr->teid == 0 || gtpu_hdr->msgtype != GTP_GPDU) {
			RESET_BIT(*pkts_mask, i);
			continue;
		}


		meta_data =
		(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(pkts[i],
						META_DATA_OFFSET);
		meta_data->teid = ntohl(gtpu_hdr->teid);
		meta_data->enb_ipv4 = ntohl(ipv4_hdr->src_addr);
		RTE_LOG(DEBUG, DP, "Received tunneled packet with teid 0x%x\n",
				meta_data->teid);
		RTE_LOG(DEBUG, DP, "From Ue IP " IPV4_ADDR "\n",
				IPV4_ADDR_FORMAT(gtpu_inner_src_ip(pkts[i])));

		ret = decap_gtpu_hdr(pkts[i]);

		if (ret < 0)
			RESET_BIT(*pkts_mask, i);
		ul_num_dcap++;

	}
}

void
gtpu_encap(void **sess_info, struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask)
{
	uint32_t i;
	struct dp_session_info *si;
	struct dp_sdf_per_bearer_info *psdf;
	struct rte_mbuf *m;
	uint16_t len;

	for (i = 0; i < n; i++) {
		psdf = (struct dp_sdf_per_bearer_info *)sess_info[i];
		if (psdf == NULL)
			continue;
		si = psdf->bear_sess_info;
		m = pkts[i];

		if (encap_gtpu_hdr(m, si->dl_s1_info.enb_teid) < 0) {
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		len = rte_pktmbuf_data_len(m);
		len = len - ETH_HDR_SIZE;

		/* construct iphdr */
		construct_ipv4_hdr(m, len, IP_PROTO_UDP, ntohl(app.s1u_ip),
				si->dl_s1_info.enb_addr.u.ipv4_addr);

		len = len - IPv4_HDR_SIZE;
		/* construct udphdr */
		construct_udp_hdr(m, len, UDP_PORT_GTPU, UDP_PORT_GTPU);
	}
}

void
ul_sess_info_get(struct rte_mbuf **pkts, uint32_t n, uint32_t *res,
		uint64_t *pkts_mask, void **sess_info)
{
	uint32_t j;
	struct ul_bm_key key[MAX_BURST_SZ];
	void *key_ptr[MAX_BURST_SZ];
	struct epc_meta_data *meta_data;
	uint64_t hit_mask = 0;

	for (j = 0; j < n; j++) {
		meta_data =
		(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(pkts[j],
							META_DATA_OFFSET);
		key[j].s1u_sgw_teid = meta_data->teid;
		key[j].rid = res[j];
		RTE_LOG(DEBUG, DP, "BEAR_SESS LKUP:UL_KEY teid:%u, rid:%u\n",
				key[j].s1u_sgw_teid, key[j].rid);
		key_ptr[j] = &key[j];
	}
	if ((iface_lookup_uplink_bulk_data((const void **)&key_ptr[0], n, &hit_mask, sess_info)) < 0)
		hit_mask = 0;

	for (j = 0; j < n; j++) {
		if (!ISSET_BIT(hit_mask, j)) {
			RESET_BIT(*pkts_mask, j);
			RTE_LOG(DEBUG, DP, "SDF BEAR LKUP:FAIL!! UL_KEY "
				"teid:%u, rid:%u\n",
				key[j].s1u_sgw_teid, key[j].rid);
			sess_info[j] = NULL;
		}
	}
}

void
adc_ue_info_get(struct rte_mbuf **pkts, uint32_t n, uint32_t *res,
		void **adc_ue_info, uint32_t flow)
{
	uint32_t j;
	struct dl_bm_key key[MAX_BURST_SZ];
	struct ipv4_hdr *ipv4_hdr;
	void *key_ptr[MAX_BURST_SZ];
	uint64_t hit_mask = 0;

	for (j = 0; j < n; j++) {
		ipv4_hdr = get_mtoip(pkts[j]);
		key[j].rid = res[j];
		if (flow == UL_FLOW)
			key[j].ue_ipv4 = ntohl(ipv4_hdr->src_addr);
		else
			key[j].ue_ipv4 = ntohl(ipv4_hdr->dst_addr);

		key_ptr[j] = &key[j];
	}

	if ((rte_hash_lookup_bulk_data(rte_adc_ue_hash,
		(const void **)&key_ptr[0], n, &hit_mask, adc_ue_info)) < 0)
		RTE_LOG(ERR, DP, "ADC UE Bulk LKUP:FAIL!!\n");

	for (j = 0; j < n; j++)
		if (!ISSET_BIT(hit_mask, j))
			adc_ue_info[j] = NULL;
}


void
dl_sess_info_get(struct rte_mbuf **pkts, uint32_t n, uint32_t *res,
		uint64_t *pkts_mask, void **sess_info)
{
	uint32_t j;
	struct ipv4_hdr *ipv4_hdr;
	void *key_ptr[MAX_BURST_SZ];
	uint64_t hit_mask = 0;

	for (j = 0; j < n; j++) {
		ipv4_hdr = get_mtoip(pkts[j]);
		struct epc_meta_data *meta_data =
		(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(pkts[j],
							META_DATA_OFFSET);
		meta_data->key.ue_ipv4 = ntohl(ipv4_hdr->dst_addr);
		meta_data->key.rid = res[j];
		RTE_LOG(DEBUG, DP, "BEAR_SESS LKUP:DL_KEY ue_addr:"IPV4_ADDR
				", rid:%u\n",
				IPV4_ADDR_HOST_FORMAT(meta_data->key.ue_ipv4),
				meta_data->key.rid);
		key_ptr[j] = &(meta_data->key);
	}
	if ((iface_lookup_downlink_bulk_data
		((const void **)&key_ptr[0], n, &hit_mask, sess_info)) < 0)
		RTE_LOG(ERR, DP, "SDF BEAR Bulk LKUP:FAIL!!\n");

	for (j = 0; j < n; j++) {
		if (!ISSET_BIT(hit_mask, j)) {
			RESET_BIT(*pkts_mask, j);
		RTE_LOG(DEBUG, DP, "SDF BEAR LKUP FAIL!! DL_KEY ue_addr:"IPV4_ADDR
				", rid:%u\n",
				IPV4_ADDR_HOST_FORMAT(((struct dl_bm_key *)key_ptr[j])->ue_ipv4),
				((struct dl_bm_key *)key_ptr[j])->rid);
			sess_info[j] = NULL;
		}
	}
}

void
get_pcc_info(void **sess_info, uint32_t n, void **pcc_info)
{
	uint32_t i;
	struct dp_sdf_per_bearer_info *psdf;

	for (i = 0; i < n; i++) {
		psdf = (struct dp_sdf_per_bearer_info *)sess_info[i];
		if (psdf == NULL) {
			pcc_info[i] = NULL;
			continue;
		}
		pcc_info[i] = &psdf->pcc_info;
	}
}

void
pcc_gating(void **sdf_info, uint32_t n, uint64_t *pkts_mask)
{
	struct dp_pcc_rules *pcc;
	struct dp_sdf_per_bearer_info *psdf;
	uint32_t i;

	for (i = 0; i < n; i++) {
		psdf = (struct dp_sdf_per_bearer_info *)sdf_info[i];
		if (psdf == NULL)
			continue;
		pcc = &psdf->pcc_info;
		if (pcc == NULL)
			continue;

		if (pcc->gate_status == CLOSE) {
			RESET_BIT(*pkts_mask, i);
			pcc->drop_pkt_count++;
		}
	}
}

/**
 * To map rating group value to index
 * @param rg_val
 *	rating group.
 * @param  rg_idx_map
 *	index map structure.
 *
 * @return
 * rating group index
 */
static uint8_t
get_rg_idx(uint32_t rg_val, struct rating_group_index_map *rg_idx_map)
{
	uint32_t i;
	for (i = 0; i < MAX_RATING_GRP; i++)
		if (rg_idx_map[i].rg_val == rg_val)
			return rg_idx_map[i].rg_idx;
	return MAX_RATING_GRP;
}

void
get_rating_grp(void **adc_ue_info, void **pcc_info,
		uint32_t **rgrp, uint32_t n)
{
	uint32_t i;
	struct dp_adc_ue_info *adc_ue;
	struct dp_adc_rules *adc;
	struct dp_pcc_rules *pcc;

	for (i = 0; i < n; i++) {
		adc_ue = adc_ue_info[i];
		pcc = pcc_info[i];
		if (adc_ue && adc_ue->adc_info.rating_group) {
			rgrp[i] = &adc->rating_group;
			continue;
		}
		if (pcc)
			rgrp[i] = &pcc->rating_group;
		else
			rgrp[i] = NULL;
	}
}

static void
update_cdr(struct ipcan_dp_bearer_cdr *cdr, struct rte_mbuf *pkt,
				uint32_t flow, enum pkt_action_t action)
{
		uint32_t charged_len;
		struct ipv4_hdr *ip_h;
		ip_h = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *,
						sizeof(struct ether_hdr) + GPDU_HDR_SIZE +
						UDP_HDR_SIZE + IPv4_HDR_SIZE);
		charged_len =
				RTE_MIN(rte_pktmbuf_pkt_len(pkt) -
								sizeof(struct ether_hdr),
								ntohs(ip_h->total_length));
		if (action == CHARGED) {
				if (flow == UL_FLOW) {
						cdr->data_vol.ul_cdr.bytes += charged_len;
						cdr->data_vol.ul_cdr.pkt_count++;
				} else {
						cdr->data_vol.dl_cdr.bytes += charged_len;
						cdr->data_vol.dl_cdr.pkt_count++;
				}	/* if (flow == UL_FLOW) */
		} else {
				if (flow == UL_FLOW) {
						cdr->data_vol.ul_drop.bytes += charged_len;
						cdr->data_vol.ul_drop.pkt_count++;
				} else {
						cdr->data_vol.dl_drop.bytes += charged_len;
						cdr->data_vol.dl_drop.pkt_count++;
				}	/* if (flow == UL_FLOW) */
		}
}

#ifdef ADC_UPFRONT
void
update_adc_cdr(void **adc_ue_info,
		struct rte_mbuf **pkts, uint32_t n,
		uint64_t *adc_pkts_mask, uint64_t *pkts_mask,
		uint32_t flow)
{
	uint32_t i;
	struct dp_adc_ue_info *adc_ue;

	for (i = 0; i < n; i++) {
		adc_ue = (struct dp_adc_ue_info *)adc_ue_info[i];
		if (adc_ue == NULL)
			continue;

		/* record cdr counts if ADC rule is open and pkt is not dropped
		 * due to pcc rule of metering.*/
		if ((ISSET_BIT(*adc_pkts_mask, i))
				&& (ISSET_BIT(*pkts_mask, i)))
			update_cdr(&adc_ue->adc_cdr, pkts[i], flow, CHARGED);

		/* record drop counts if ADC rule is hit but gate is closed*/
		if (!(ISSET_BIT(*adc_pkts_mask, i)))
			update_cdr(&adc_ue->adc_cdr, pkts[i], flow, DROPPED);
	
	
	
	}	/* for (i = 0; i < n; i++)*/
}
#endif /* ADC_UPFRONT*/

void
update_sdf_cdr(void **adc_ue_info, void **sdf_bear_info,
		struct rte_mbuf **pkts, uint32_t n,
		uint64_t *adc_pkts_mask, uint64_t *pkts_mask,
		uint32_t flow)
{
	uint32_t i;
	struct dp_sdf_per_bearer_info *psdf;
	struct dp_adc_ue_info *adc_ue;

	for (i = 0; i < n; i++) {
		psdf = (struct dp_sdf_per_bearer_info *)sdf_bear_info[i];
		if (psdf == NULL)
			continue;
		/* if ADC rule is hit, but gate is closed
		 * then don't update PCC cdr. */
		adc_ue = (struct dp_adc_ue_info *)adc_ue_info[i];
		if ((adc_ue != NULL)
				&& !ISSET_BIT(*adc_pkts_mask, i))
			continue;

		/* if ADC CDR is updated, then no need to
		 * update PCC cdr */
		if (ISSET_BIT(*adc_pkts_mask, i))
			continue;

		if (ISSET_BIT(*pkts_mask, i))
			update_cdr(&psdf->sdf_cdr, pkts[i], flow, CHARGED);
		else
			update_cdr(&psdf->sdf_cdr, pkts[i], flow, DROPPED);
	}	/* for (i = 0; i < n; i++)*/
}

void
update_bear_cdr(void **sdf_bear_info,
		struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint32_t flow)
{
	uint32_t i;
	struct dp_session_info *si;
	struct dp_sdf_per_bearer_info *psdf;

	for (i = 0; i < n; i++) {
		psdf = (struct dp_sdf_per_bearer_info *)sdf_bear_info[i];
		if (psdf == NULL)
			continue;

		si = psdf->bear_sess_info;
		if (si == NULL)
			continue;

		if (ISSET_BIT(*pkts_mask, i))
			update_cdr(&si->ipcan_dp_bearer_cdr, pkts[i], flow, CHARGED);
		else
			update_cdr(&si->ipcan_dp_bearer_cdr, pkts[i], flow, DROPPED);
	}	/* for (i = 0; i < n; i++)*/
}

void
update_rating_grp_cdr(void **sess_info, uint32_t **rgrp,
		struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint32_t flow)
{
	uint32_t i;
	struct dp_session_info *si;
	struct dp_sdf_per_bearer_info *psdf;
	uint8_t rg_idx;

	for (i = 0; i < n; i++) {
		psdf = (struct dp_sdf_per_bearer_info *)sess_info[i];
		if (psdf == NULL)
			continue;

		si = psdf->bear_sess_info;
		if (si == NULL)
			continue;

		if (rgrp[i] == NULL)
			continue;

		rg_idx = get_rg_idx(*rgrp[i], si->ue_info_ptr->rg_idx_map);
		if (rg_idx >= MAX_RATING_GRP)
			continue;

		if (ISSET_BIT(*pkts_mask, i))
			update_cdr(&si->ue_info_ptr->rating_grp[rg_idx], pkts[i], flow, CHARGED);
		else
			update_cdr(&si->ue_info_ptr->rating_grp[rg_idx], pkts[i], flow, DROPPED);
	}	/* for (i = 0; i < n; i++)*/
}

#ifdef SDF_MTR
void
get_sdf_mtr_id(void **sess_info, void **mtr_id,
					uint64_t **mtr_drops, uint32_t n)
{
	uint32_t i;
	struct dp_sdf_per_bearer_info *psdf;

	for (i = 0; i < n; i++) {
		if (!ISSET_BIT(*pkts_mask, i))
			continue;
		psdf = (struct dp_sdf_per_bearer_info *)sess_info[i];
		if (psdf == NULL) {
			mtr_id[i] = NULL;
			continue;
		}
		mtr_id[i] = &psdf->sdf_mtr_obj;
		mtr_drops[i] = &psdf->sdf_mtr_drops;
		RTE_LOG(DEBUG, DP, "SDF MTR LKUP: mtr_obj:0x%"PRIx64"\n",
				(uint64_t)&psdf->sdf_mtr_obj);
	}
}
#endif /* SDF_MTR */
#ifdef APN_MTR
void
get_apn_mtr_id(void **sess_info, void **mtr_id,
					uint64_t **mtr_drops, uint32_t n)
{
	uint32_t i;
	struct dp_session_info *si;
	struct dp_sdf_per_bearer_info *psdf;
	struct ue_session_info *ue;

	for (i = 0; i < n; i++) {
		if (!ISSET_BIT(*pkts_mask, i))
			continue;
		psdf = (struct dp_sdf_per_bearer_info *)sess_info[i];
		if (psdf == NULL) {
			mtr_id[i] = NULL;
			continue;
		}
		si = psdf->bear_sess_info;
		ue = si->ue_info_ptr;
		mtr_id[i] = &ue->apn_mtr_obj;
		mtr_drops[i] = &ue->apn_mtr_drops;
		RTE_LOG(DEBUG, DP, "BEAR_SESS MTR LKUP: apn_mtr_id:%u, "
				"apn_mtr_obj:0x%"PRIx64"\n",
				si->apn_mtr_idx, (uint64_t)mtr_id[i]);
	}
}
#endif /* APN_MTR */
void
adc_hash_lookup(struct rte_mbuf **pkts, uint32_t n, uint32_t *rid, uint8_t flow)
{
	uint32_t j;
	uint32_t key32[MAX_BURST_SZ];
	uint32_t *key_ptr[MAX_BURST_SZ];
	uint64_t hit_mask = 0;
	int ret = 0;
	struct msg_adc *data[MAX_BURST_SZ];
	struct ipv4_hdr *ipv4_hdr;

	for (j = 0; j < n; j++) {
		ipv4_hdr = get_mtoip(pkts[j]);
		key32[j] = (flow == UL_FLOW) ? ipv4_hdr->dst_addr : ipv4_hdr->src_addr;
		key_ptr[j] = &key32[j];
	}

	if (iface_lookup_adc_bulk_data((const void **)key_ptr,
			n, &hit_mask, (void **)data) < 0)
		hit_mask = 0;

	for (j = 0; j < n; j++) {
		if (ISSET_BIT(hit_mask, j)) {
			RTE_LOG(DEBUG, DP, "ADC_DNS_LKUP: rid[%d]:%u\n", j, data[j]->rule_id);
			rid[j] = data[j]->rule_id;
		} else {
			rid[j] = 0;
		}
	}
}

static inline bool is_dns_pkt(struct rte_mbuf *m, uint32_t rid)
{
	struct ipv4_hdr *ip_hdr;
	struct ether_hdr *eth_hdr;

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);

	if (rte_ipv4_frag_pkt_is_fragmented(ip_hdr))
		return false;

	if (rid != DNS_RULE_ID)
		return false;

	return true;
}

void
update_dns_meta(struct rte_mbuf **pkts, uint32_t n, uint32_t *rid)
{
	uint32_t i;
	struct epc_meta_data *meta_data;
	for (i = 0; i < n; i++) {

		meta_data =
			(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(pkts[i], META_DATA_OFFSET);

		if (likely(!is_dns_pkt(pkts[i], rid[i]))) {
			meta_data->dns = 0;
			continue;
		}

		meta_data->dns = 1;
	}
}

static int get_worker_index(unsigned lcore_id)
{
	int i;

	for (i = 0; i < epc_app.num_workers; ++i)
		if (epc_app.worker_cores[i] == lcore_id)
			return i;
}

void
clone_dns_pkts(struct rte_mbuf **pkts, uint32_t n, uint64_t pkts_mask)
{
	uint32_t i;
	struct epc_meta_data *meta_data;
	unsigned lcore_id = rte_lcore_id();
	int worker_index = get_worker_index(lcore_id);

	unsigned dns_payload_off =sizeof(struct ether_hdr) +sizeof(struct ipv4_hdr) +sizeof(struct udp_hdr);
	for (i = 0; i < n; i++) {
		if (ISSET_BIT(pkts_mask, i)) {
			meta_data =
			(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(
						pkts[i], META_DATA_OFFSET);
			
			++(epc_app.worker[worker_index].num_gets);
			
			if (meta_data->dns) {
				push_dns_ring(pkts[i]);
				++(epc_app.worker[worker_index].num_dns_packets);
			}
			//printf("checked length %d\n",rte_pktmbuf_data_len(pkts[i]-dns_payload_off));
			if(rte_pktmbuf_data_len(pkts[i])<dns_payload_off)
				go++;
			else	
				offline_scan(rte_pktmbuf_mtod(pkts[i], char *)+dns_payload_off,150);//rte_pktmbuf_data_len(pkts[i])-dns_payload_off);
		}
	}
}

void
update_nexthop_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint8_t portid)
{
	uint32_t i;
	for (i = 0; i < n; i++) {
		if (ISSET_BIT(*pkts_mask, i)) {
			if (construct_ether_hdr(pkts[i], portid) < 0)
				RESET_BIT(*pkts_mask, i);
		}
		/* TODO: Set checksum offload.*/
	}
}

void
update_adc_rid_from_domain_lookup(uint32_t *rb, uint32_t *rc, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (rc[i] != 0)
			rb[i] = rc[i];
}

