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

/**
 * pkt_handler.c: Main processing for uplink and downlink packets.
 * This is done by the worker core in the pipeline.
 */

#include <unistd.h>
#include <locale.h>

#include "main.h"
#include "acl.h"
//#include "stat.h"
int
s1u_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n)
{
	void *sdf_info[MAX_BURST_SZ];
	void *adc_info[MAX_BURST_SZ];
	void *adc_ue_info[MAX_BURST_SZ];
	void *pcc_info[MAX_BURST_SZ];
	void *mtr_id[MAX_BURST_SZ];
	uint64_t *mtr_drp_cnt[MAX_BURST_SZ];
	uint32_t *r_grp[MAX_BURST_SZ];
	uint32_t *pcc_rule_id;
	uint32_t *adc_rule_a;
	uint32_t adc_rule_b[MAX_BURST_SZ];
	void *base_addr, *acl_search;
	uint64_t pkts_mask;
	uint64_t adc_pkts_mask = 0;

	pkts_mask = (~0LLU) >> (64 - n);

	/* Decap GTPU and update meta data*/
	gtpu_decap(pkts, n, &pkts_mask);

	/* SDF table lookup*/
	pcc_rule_id = sdf_lookup(pkts, n);

#ifdef ADC_UPFRONT
	/* ADC table lookup*/
	adc_rule_a = adc_ul_lookup(pkts, n);

	/* ADC Hash table lookup*/
	adc_hash_lookup(pkts, n, &adc_rule_b[0], UL_FLOW);

	/* if adc rule is found in adc domain name table (from hash lookup),
	 * overwrite the result from filter table.	*/
	update_adc_rid_from_domain_lookup(adc_rule_a, &adc_rule_b[0], n);

	/* get ADC UE info struct*/
	adc_ue_info_get(pkts, n, adc_rule_a, &adc_ue_info[0], UL_FLOW);

	adc_gating(adc_rule_a, &adc_ue_info[0], n, &adc_pkts_mask, &pkts_mask);

#endif /*ADC_UPFRONT*/

	/* get per SDF, bearer session info*/
	ul_sess_info_get(pkts, n, pcc_rule_id, &pkts_mask, &sdf_info[0]);

	/* PCC Gating*/
	pcc_gating(&sdf_info[0], n, &pkts_mask);

	/* Metering */
#ifdef SDF_MTR
	get_sdf_mtr_id(&sdf_info[0], &mtr_id[0], &mtr_drp_cnt[0], n);

	mtr_process_pkt(&mtr_id[0], &mtr_drp_cnt[0], pkts, n, &pkts_mask);
#endif	/* SDF_MTR */

#ifdef APN_MTR
	get_apn_mtr_id(&sdf_info[0], &mtr_id[0], &mtr_drp_cnt[0], n);

	mtr_process_pkt(&mtr_id[0], &mtr_drp_cnt[0], pkts, n, &pkts_mask);
#endif	/* APN_MTR */

	/* Update CDRs*/
#ifdef ADC_UPFRONT
	update_adc_cdr(&adc_ue_info[0], pkts, n, &adc_pkts_mask, &pkts_mask, UL_FLOW);
#endif

	update_sdf_cdr(&adc_ue_info[0], &sdf_info[0], pkts, n, &adc_pkts_mask, &pkts_mask, UL_FLOW);

	update_bear_cdr(&sdf_info[0], pkts, n, &pkts_mask, UL_FLOW);

#ifdef RATING_GRP_CDR
	get_rating_grp(&adc_ue_info[0], &pcc_info[0], &r_grp[0], n);

	update_rating_grp_cdr(&sdf_info[0], &r_grp[0], pkts, n, &pkts_mask, UL_FLOW);
#endif	/* RATING_GRP_CDR */

	/* Update nexthop L2 header*/
	update_nexthop_info(pkts, n, &pkts_mask, app.sgi_port);

	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);

	return 0;
}

/**
 * Process Downlink traffic: sdf and adc filter, metering, charging and encap gtpu.
 * Update adc hash if dns reply is found with ip addresses.
 */
int
sgi_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n)
{
	void *sdf_info[MAX_BURST_SZ];
	void *adc_info[MAX_BURST_SZ];
	void *adc_ue_info[MAX_BURST_SZ];
	void *pcc_info[MAX_BURST_SZ];
	void *mtr_id[MAX_BURST_SZ];
	uint64_t *mtr_drp_cnt[MAX_BURST_SZ];
	uint32_t *r_grp[MAX_BURST_SZ];
	uint32_t *pcc_rule_id;
	uint32_t *adc_rule_a;
	uint32_t adc_rule_b[MAX_BURST_SZ];
	void *base_addr, *acl_search;
	uint64_t pkts_mask;
	uint64_t adc_pkts_mask = 0;

	pkts_mask = (~0LLU) >> (64 - n);

	/* SDF table lookup*/
	pcc_rule_id = sdf_lookup(pkts, n);

#ifdef ADC_UPFRONT
	/* ADC table lookup*/
	adc_rule_a = adc_dl_lookup(pkts, n);

	/* Identify the DNS rule and update the meta*/
	update_dns_meta(pkts, n, adc_rule_a);

	/* ADC Hash table lookup*/
	adc_hash_lookup(pkts, n, &adc_rule_b[0], DL_FLOW);

	/* if adc rule is found in adc domain name table (from hash lookup),
	 * overwrite the result from filter table.	*/
	update_adc_rid_from_domain_lookup(adc_rule_a, &adc_rule_b[0], n);

	/* get ADC UE info*/
	adc_ue_info_get(pkts, n, adc_rule_a, &adc_ue_info[0], DL_FLOW);

	adc_gating(adc_rule_a, &adc_ue_info[0], n, &adc_pkts_mask, &pkts_mask);

#endif	/* ADC_UPFRONT */

	/* get per SDF, bearer session info*/
	dl_sess_info_get(pkts, n, pcc_rule_id, &pkts_mask, &sdf_info[0]);

	/* PCC Gating*/
	pcc_gating(&sdf_info[0], n, &pkts_mask);

	/* Metering */
#ifdef SDF_MTR
	get_sdf_mtr_id(&sdf_info[0], &mtr_id[0], &mtr_drp_cnt[0], n);

	mtr_process_pkt(&mtr_id[0], &mtr_drp_cnt[0], pkts, n, &pkts_mask);
#endif	/* SDF_MTR */

#ifdef APN_MTR
	get_apn_mtr_id(&sdf_info[0], &mtr_id[0], &mtr_drp_cnt[0], n);

	mtr_process_pkt(&mtr_id[0], &mtr_drp_cnt[0], pkts, n, &pkts_mask);
#endif	/* APN_MTR */

	/* Update CDRs*/
#ifdef ADC_UPFRONT
	update_adc_cdr(&adc_ue_info[0], pkts, n, &adc_pkts_mask, &pkts_mask, DL_FLOW);
#endif

	update_sdf_cdr(&adc_ue_info[0], &sdf_info[0], pkts, n, &adc_pkts_mask, &pkts_mask, DL_FLOW);

	update_bear_cdr(&sdf_info[0], pkts, n, &pkts_mask, DL_FLOW);

#ifdef RATING_GRP_CDR
	get_rating_grp(&adc_ue_info[0], &pcc_info[0], &r_grp[0], n);

	update_rating_grp_cdr(&sdf_info[0], &r_grp[0], pkts, n, &pkts_mask, DL_FLOW);
#endif	/* RATING_GRP_CDR */

#ifdef HYPERSCAN_DPI
	/* Send cloned dns pkts to dns handler*/
	clone_dns_pkts(pkts, n, pkts_mask);
#endif	/* HYPERSCAN_DPI */

	/* Encap GTPU header*/
	gtpu_encap(&sdf_info[0], pkts, n, &pkts_mask);

	/* Update nexthop L2 header*/
	update_nexthop_info(pkts, n, &pkts_mask, app.s1u_port);
	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);
	//Idisplay_dns_stats();
	return 0;
}
