/*
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

#ifndef _ACL_H_
#define _ACL_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of Access Control List.
 */
#include <rte_acl.h>
#include <rte_ip.h>

#include "vepc_cp_dp_api.h"

#define MAX_ACL_RULE_NUM	100000
/**
 * Max pkt filter precedence.
 */
#define MAX_FILTER_PRECE 0x1fffffff

/**
 * DNS filter rule precedence.
 */
#define DNS_FILTER_PRECE MAX_FILTER_PRECE

uint64_t acl_rule_stats[MAX_ACL_RULE_NUM];

/**
 * Function for SDF lookup.
 *
 * @param m
 *	pointer to pkts.
 * @param nb_rx
 *	num. of pkts.
 *
 * @return
 *	array containing search results for each input buf
 */
uint32_t *
sdf_lookup(struct rte_mbuf **m, int nb_rx);

/**
 * Function for ADC table lookup for Upsstream traffic.
 *
 * @param m
 *	pointer to pkts.
 * @param nb_rx
 *	num. of pkts.
 *
 * @return
 *	array containing search results for each input buf
 */
uint32_t *
adc_ul_lookup(struct rte_mbuf **m, int nb_rx);
/**
 * Function for ADC table lookup for Downsstream traffic.
 *
 * @param m
 *	pointer to pkts.
 * @param nb_rx
 *	num. of pkts.
 *
 * @return
 *	array containing search results for each input buf
 */
uint32_t *
adc_dl_lookup(struct rte_mbuf **m, int nb_rx);

/**
 * Get SDF ACL table base address.
 *
 * @return
 *	void
 */
void get_sdf_table_base(void **ba, void **as);

/**
 * Get ADC ACL table base address.
 * @param ba
 *	base address of acl config.
 * @param as
 *	base address of acl search struct.
 *
 */
void get_adc_table_base(void **ba, void **as);

/******************** DP SDF functions **********************/
/**
 *  Create SDF rules table
 *
 * @param dp_id
 *	identifier which is unique across DataPlanes.
 * @param max_elements
 *	max number of elements in this table.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_sdf_filter_table_create(struct dp_id dp_id, uint32_t max_elements);
/**
 *  Delete SDF rules table
 *
 * @param dp_id
 *	identifier which is unique across DataPlanes.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_sdf_filter_table_delete(struct dp_id dp_id);

/**
 *  Add SDF rules
 *
 * @param dp_id
 *	identifier which is unique across DataPlanes.
 * @param  pkt_filter_entry
 *	sdf packet filter entry structure
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_sdf_filter_entry_add(struct dp_id dp_id, struct pkt_filter *pkt_filter);

/**
 * Delete SDF rules.
 *
 * @param dp_id
 *	identifier which is unique across DataPlanes.
 * @param  pkt_filter_entry
 *	sdf packet filter entry structure
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_sdf_filter_entry_delete(struct dp_id dp_id,
				struct pkt_filter *pkt_filter_entry);

/******************** DP ADC functions **********************/
/**
 *  Create ADC rules table
 *
 * @param dp_id
 *	identifier which is unique across DataPlanes.
 * @param max_elements
 *	max number of elements in this table.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_adc_filter_table_create(struct dp_id dp_id, uint32_t max_elements);

/**
 *  Delete ADC rules table
 *
 * @param dp_id
 *	identifier which is unique across DataPlanes.
 * @param max_elements
 *	max number of elements in this table.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_adc_filter_table_delete(struct dp_id dp_id);

/**
 *  Add ADC rules
 *
 * @param dp_id
 *	identifier which is unique across DataPlanes.
 * @param  pkt_filter_entry
 *	sdf packet filter entry structure
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_adc_filter_entry_add(struct dp_id dp_id, struct pkt_filter *pkt_filter);

/**
 * Delete ADC rules.
 *
 * @param dp_id
 *	identifier which is unique across DataPlanes.
 * @param  pkt_filter_entry
 *	sdf packet filter entry structure
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_adc_filter_entry_delete(struct dp_id dp_id,
				struct pkt_filter *pkt_filter_entry);

#endif /* _ACL_H_ */

