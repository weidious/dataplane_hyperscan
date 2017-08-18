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

#define _GNU_SOURCE     /* Expose declaration of tdestroy() */
#include <search.h>
#include <rte_mbuf.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_cfgfile.h>
#include <rte_hash.h>


#include "vepc_cp_dp_api.h"
#include "main.h"
#include "util.h"
#include "acl.h"
#include "interface.h"
#include "cdr.h"
#include "meter.h"

#define SESS_CREATE 0
#define SESS_MODIFY 1
#define SESS_DEL 2

extern struct rte_hash *rte_sess_hash;
extern struct rte_hash *rte_ue_hash;
extern struct rte_hash *rte_uplink_hash;
extern struct rte_hash *rte_downlink_hash;
extern struct rte_hash *rte_adc_hash;
extern struct rte_hash *rte_adc_ue_hash;
extern struct table adc_table;

/** Function used to compare keys */
typedef int (*rte_hash_cmp_eq_t) (const void *key1, const void *key2,
		size_t key_len);
/** Structure storing both primary and secondary hashes */
struct rte_hash_signatures {
	union {
		struct {
			hash_sig_t current;
			hash_sig_t alt;
		};
		uint64_t sig;
	};
};

#define RTE_HASH_BUCKET_ENTRIES         4
/** Bucket structure */
struct rte_hash_bucket {
	struct rte_hash_signatures signatures[RTE_HASH_BUCKET_ENTRIES];
	/** Includes dummy key index that always contains index 0 */
	uint32_t key_idx[RTE_HASH_BUCKET_ENTRIES + 1];
	uint8_t flag[RTE_HASH_BUCKET_ENTRIES];
} __rte_cache_aligned;

/** A hash table structure. */
struct rte_hash {
	char name[RTE_HASH_NAMESIZE];
	/** Total table entries. */
	uint32_t entries;
	/** Number of buckets in table. */
	uint32_t num_buckets;
	/** Length of hash key. */
	uint32_t key_len;
	/** Function used to calculate hash. */
	rte_hash_function hash_func;
	/** Init value used by hash_func. */
	uint32_t hash_func_init_val;
	/** Function used to compare keys. */
	rte_hash_cmp_eq_t rte_hash_cmp_eq;
	/** Bitmask for getting bucket index from hash signature */
	uint32_t bucket_bitmask;
	/** Size of each key entry. */
	uint32_t key_entry_size;
	/** Ring that stores all indexes of the free slots in the key table*/
	struct rte_ring *free_slots;
	/** Table storing all keys and data */
	void *key_store;
	/** Table with buckets storing all the hash values and key indexes
	 * to the key table
	 */
	struct rte_hash_bucket *buckets;
} __rte_cache_aligned;

int
iface_lookup_uplink_data(struct ul_bm_key *key,
		void **value)
{
	/* check if rte hash exists*/
	if (unlikely(rte_uplink_hash == NULL)) {
		RTE_LOG(NOTICE, DP, "UL iface not yet setup\n");
		return -1;
	}

	return rte_hash_lookup_data(rte_uplink_hash, key, value);
}

int
iface_lookup_uplink_bulk_data(const void **key, uint32_t n,
		uint64_t *hit_mask, void **value)
{
	/* check if rte hash exists*/
	if (unlikely(rte_uplink_hash == NULL)) {
		RTE_LOG(NOTICE, DP, "UL iface not yet setup\n");
		return -1;
	}

	return rte_hash_lookup_bulk_data(rte_uplink_hash, key, n, hit_mask, value);
}

int
iface_lookup_downlink_data(struct dl_bm_key *key,
		void **value)
{
	/* check if rte hash exists*/
	if (unlikely(rte_downlink_hash == NULL)) {
		RTE_LOG(NOTICE, DP, "DL iface not yet setup\n");
		return -1;
	}
	return rte_hash_lookup_data(rte_downlink_hash, key, value);
}

int
iface_lookup_downlink_bulk_data(const void **key, uint32_t n,
		uint64_t *hit_mask, void **value)
{
    /* check if rte hash exists*/
    if (unlikely(rte_downlink_hash == NULL)) {
		RTE_LOG(NOTICE, DP, "DL iface not yet setup\n");
		return -1;
	}

	return rte_hash_lookup_bulk_data(rte_downlink_hash, key, n, hit_mask, value);
}

int
iface_lookup_adc_ue_data(struct dl_bm_key *key,
		void **value)
{
	/* check if rte hash exists*/
	if (unlikely(rte_adc_ue_hash == NULL)) {
		RTE_LOG(NOTICE, DP, "rte_adc_ue_hash not yet setup\n");
		return -1;
	}
	return rte_hash_lookup_data(rte_adc_ue_hash, key, value);
}

/******************** DP- ADC, PCC funcitons **********************/
int iface_lookup_adc_data(const uint32_t key32,
		void **value)
{
	/* check if rte hash exists*/
	if (unlikely(rte_adc_hash == NULL)) {
		RTE_LOG(NOTICE, DP, "ADC iface not yet setup\n");
		return -1;
	}
	return rte_hash_lookup_data(rte_adc_hash, &key32, (void **)value);
}

int iface_lookup_adc_bulk_data(const void **key, uint32_t n,
		uint64_t *hit_mask, void **value)
{
	/* check if rte hash exists*/
	if (unlikely(rte_adc_hash == NULL)) {
		RTE_LOG(NOTICE, DP, "ADC iface not yet setup\n");
		return -1;
	}
	return rte_hash_lookup_bulk_data(rte_adc_hash, key, n, hit_mask, value);
}
struct rte_hash_bucket *bucket_ul_addr(uint64_t key)
{
	uint32_t bucket_idx;
	hash_sig_t sig = rte_hash_hash(rte_uplink_hash, &key);

	bucket_idx = sig & rte_uplink_hash->bucket_bitmask;
	return &rte_uplink_hash->buckets[bucket_idx];
}

struct rte_hash_bucket *bucket_dl_addr(uint64_t key)
{
	uint32_t bucket_idx;
	hash_sig_t sig = rte_hash_hash(rte_downlink_hash, &key);

	bucket_idx = sig & rte_downlink_hash->bucket_bitmask;
	return &rte_downlink_hash->buckets[bucket_idx];
}

int
add_rg_idx(uint32_t rg_val, struct rating_group_index_map *rg_idx_map)
{
	uint32_t i;

	for (i = 0; i < MAX_RATING_GRP; i++) {

		if ((rg_idx_map+i)->rg_val == rg_val)
			return 0;

		if ((rg_idx_map+i)->rg_val == 0) {
			(rg_idx_map+i)->rg_val = rg_val;
			return 0;
		}
	}
	return -1;
}

/********************* PCC rules update functions ***********************/
/**
 * @brief Function to add UL pcc entry with key and
 * update pcc address and rating group.
 *
 */
static void
add_ul_pcc_entry_key_with_idx(struct dp_session_info *old,
			struct dp_session_info *data, uint32_t idx)
{
	int ret;
	struct ul_bm_key ul_key;
	struct dp_pcc_rules *pcc_info;
	uint32_t pcc_id;
	struct dp_sdf_per_bearer_info *psdf;

	pcc_id = data->ul_pcc_rule_id[idx];
	if (pcc_id == 0)
		return;

	/* get pcc rule info address*/
	iface_lookup_pcc_data(pcc_id, &pcc_info);
	old->ul_pcc_rule_id[idx] = pcc_id;

	/* update rating group idx*/
	if (old->ue_info_ptr != NULL) {
		ret = add_rg_idx(pcc_info->rating_group, old->ue_info_ptr->rg_idx_map);
		if (ret)
			rte_panic("Failed to add rating group to index map");
	}

	/* alloc memory for per sdf per bearer info structure*/
	psdf = rte_zmalloc("sdf per bearer", sizeof(struct dp_sdf_per_bearer_info),
			RTE_CACHE_LINE_SIZE);
	if (psdf == NULL) {
		RTE_LOG(ERR, DP, "Failed to allocate memory for sdf per bearer info");
		return ;
	}
	psdf->pcc_info = *pcc_info;
	psdf->bear_sess_info = old;
#ifdef SDF_MTR
	mtr_cfg_entry(pcc_info->mtr_profile_index, &psdf->sdf_mtr_obj);
#endif	/* SDF_MTR */

	ul_key.s1u_sgw_teid = data->ul_s1_info.sgw_teid;
	ul_key.rid = pcc_id;

	RTE_LOG(DEBUG, DP, "BEAR_SESS ADD:UL_KEY: teid:%u, rid:%u,",
			ul_key.s1u_sgw_teid, ul_key.rid);

	ret = rte_hash_add_key_data(rte_uplink_hash,
			&ul_key, psdf);
	if (ret < 0)
		rte_panic("Failed to add entry in hash table");
}

/**
 * @brief Function to del UL pcc entry with key and
 * update pcc address and rating group.
 *
 */
static void
del_ul_pcc_entry_key_with_idx(struct dp_session_info *data, uint32_t idx)
{
	int ret;
	struct ul_bm_key ul_key;
	struct dp_sdf_per_bearer_info *psdf;

	ul_key.s1u_sgw_teid = data->ul_s1_info.sgw_teid;
	ul_key.rid = data->ul_pcc_rule_id[idx];

	RTE_LOG(DEBUG, DP, "BEAR_SESS DEL:UL_KEY: teid:%u, rid:%u\n",
			ul_key.s1u_sgw_teid, ul_key.rid);

	if (ul_key.rid == 0)
		return;

	/* Get the sdf per bearer info */
	ret = iface_lookup_uplink_data(&ul_key, (void **)&psdf);
	if (ret < 0) {
		RTE_LOG(DEBUG, DP, "BEAR_SESS DEL FAIL:UL_KEY: teid:%u, rid:%u\n",
			ul_key.s1u_sgw_teid, ul_key.rid);
		return ;
	}

	ret = rte_hash_del_key(rte_uplink_hash,
			&ul_key);
	if (ret == -ENOENT)
		RTE_LOG(DEBUG, DP, "key is not found\n");
	if (ret == -EINVAL)
		RTE_LOG(DEBUG, DP, "Invalid Params: Failed to del from hash table");
	if (ret < 0)
		rte_panic("Failed to del entry from hash table");

	/* remove sdf per bearer info from session hash table*/
	rte_free(psdf);
}

/**
 * @brief Function to add DL pcc entry with key and
 * update pcc address and rating group.
 *
 */
static void
add_dl_pcc_entry_key_with_idx(struct dp_session_info *old,
			struct dp_session_info *data, uint32_t idx)
{
	int ret;
	struct dl_bm_key dl_key;
	struct dp_pcc_rules *pcc_info = NULL;
	uint32_t pcc_id;
	struct dp_sdf_per_bearer_info *psdf;

	pcc_id = data->dl_pcc_rule_id[idx];
	if (pcc_id == 0)
		return;

	/* get pcc rule info address*/
	iface_lookup_pcc_data(pcc_id, &pcc_info);
	if (pcc_info == NULL)
		return;
	old->dl_pcc_rule_id[idx] = pcc_id;

	/* update rating group idx*/
	if (old->ue_info_ptr != NULL) {
		ret = add_rg_idx(pcc_info->rating_group, old->ue_info_ptr->rg_idx_map);
		if (ret)
			rte_panic("Failed to add rating group to index map");
	}

	/* alloc memory for per sdf per bearer info */
	psdf = rte_zmalloc("sdf per bearer", sizeof(struct dp_sdf_per_bearer_info),
			RTE_CACHE_LINE_SIZE);
	if (psdf == NULL) {
		RTE_LOG(ERR, DP, "Failed to allocate memory for sdf per bearer info");
		return ;
	}
	psdf->pcc_info = *pcc_info;
	psdf->bear_sess_info = old;

#ifdef SDF_MTR
	mtr_cfg_entry(pcc_info->mtr_profile_index, &psdf->sdf_mtr_obj);
#endif	/* SDF_MTR */

	dl_key.ue_ipv4 = old->ue_addr.u.ipv4_addr;
	dl_key.rid = pcc_id;

	RTE_LOG(DEBUG, DP, "BEAR_SESS ADD:DL_KEY: ue_addr:"IPV4_ADDR ",",
			IPV4_ADDR_HOST_FORMAT(dl_key.ue_ipv4));

	ret = rte_hash_add_key_data(rte_downlink_hash,
			&dl_key, psdf);

	if (ret < 0)
		rte_panic("Failed to add entry in hash table");
}

/**
 * @brief Function to del DL pcc entry with key and
 * update pcc address and rating group.
 *
 */
static void
del_dl_pcc_entry_key_with_idx(struct dp_session_info *data, uint32_t idx)
{
	int ret;
	struct dl_bm_key dl_key;
	struct dp_sdf_per_bearer_info *psdf;

	dl_key.ue_ipv4 = data->ue_addr.u.ipv4_addr;
	dl_key.rid = data->dl_pcc_rule_id[idx];

	if (dl_key.rid == 0)
		return;

	RTE_LOG(DEBUG, DP, "BEAR_SESS DEL:DL_KEY: pcc_id: %d, ue_addr:"IPV4_ADDR ",",
		dl_key.rid, IPV4_ADDR_HOST_FORMAT(dl_key.ue_ipv4));

	/* Get the sdf per bearer info */
	ret = iface_lookup_downlink_data(&dl_key, (void **)&psdf);
	if (ret < 0) {
		RTE_LOG(DEBUG, DP, "BEAR_SESS DEL FAIL:DL_KEY: ue_addr:"IPV4_ADDR ",",
			IPV4_ADDR_HOST_FORMAT(dl_key.ue_ipv4));
		return ;
	}

	ret = rte_hash_del_key(rte_downlink_hash,
			&dl_key);
	if (ret < 0)
		rte_panic("Failed to del entry from hash table");

	/* remove sdf per bearer info from session hash table*/
	rte_free(psdf);
}

/**
 * @brief Check for change in PCC rule.
 */
static void
update_pcc_rules(struct dp_session_info *old,
			struct dp_session_info *new)
{
	uint32_t i;
	uint32_t *p1;
	uint32_t *p2;
	uint32_t n1;
	uint32_t n2;
	uint32_t n;

	/* Modify UL PCC rule keys*/
	p1 = old->ul_pcc_rule_id;
	p2 = new->ul_pcc_rule_id;
	n1 = old->num_ul_pcc_rules;
	n2 = new->num_ul_pcc_rules;
	n = (n1 > n2) ? (n2) : (n1);
	for (i = 0; i < n; i++)
		if (p1[i] != p2[i]) {
			del_ul_pcc_entry_key_with_idx(old, i);
			add_ul_pcc_entry_key_with_idx(old, new, i);
		}

	if (n1 > n2)
		while (i < n1) {
			del_ul_pcc_entry_key_with_idx(old, i);
			i++;
		}
	else if (n1 < n2)
		while (i < n2) {
			add_ul_pcc_entry_key_with_idx(old, new, i);
			i++;
		}

	old->num_ul_pcc_rules = n2;

	/* Modify DL PCC rule keys*/
	p1 = old->dl_pcc_rule_id;
	p2 = new->dl_pcc_rule_id;
	n1 = old->num_dl_pcc_rules;
	n2 = new->num_dl_pcc_rules;
	n = (n1 > n2) ? (n2) : (n1);
	for (i = 0; i < n; i++)
		if (p1[i] != p2[i]) {
			del_dl_pcc_entry_key_with_idx(old, i);
			add_dl_pcc_entry_key_with_idx(old, new, i);
		}
	if (n1 > n2)
		while (i < n1) {
			del_dl_pcc_entry_key_with_idx(old, i);
			i++;
		}
	else if (n1 < n2)
		while (i < n2) {
			add_dl_pcc_entry_key_with_idx(old, new, i);
			i++;
		}
	old->num_dl_pcc_rules = n2;
}

/******************** ADC rules update functions **************/
/**
 * @brief Function to copy fields from struct adc_rules to
 * struct dp_adc_rules. *
 */

static void
copy_dp_adc_rules(struct dp_adc_rules *dst,
		struct adc_rules *src)
{
	dst->rule_id = src->rule_id;
	dst->rating_group = src->rating_group;
	dst->gate_status = src->gate_status;
	dst->report_level = src->report_level;
	dst->mute_notify = src->mute_notify;
	dst->rule_activation_time = src->rule_activation_time;
	dst->rule_deactivation_time = src->rule_deactivation_time;
	dst->redirect_info = src->redirect_info;
}
/**
 * @brief Function to add adc entry with key and
 * update adc address and rating group.
 *
 */
static void
add_adc_entry_key_with_idx(struct ue_session_info *old,
			struct ue_session_info *new, uint32_t idx)
{
	int ret;
	struct dl_bm_key key;
	struct adc_rules *adc_info;
	uint32_t adc_id;
	uint64_t pkts_mask = 1;
	struct dp_adc_ue_info *padc_ue;
	void *data = NULL;

	adc_id = new->adc_rule_id[idx];
	if (adc_id == 0)
		return;
	key.ue_ipv4 = old->ue_addr.u.ipv4_addr;
	key.rid = adc_id;

	ret = rte_hash_lookup_data(rte_adc_ue_hash, &key, &data);
	if (data)
		return;

	/* get adc rule info address*/
	adc_rule_info_get(&adc_id, 1, &pkts_mask, (void **)&adc_info);
	old->adc_rule_id[idx] = adc_id;

	/* update rating group idx*/
	ret = add_rg_idx(adc_info->rating_group, old->rg_idx_map);
	if (ret)
			rte_panic("Failed to add rating group to index map");

	/* alloc memory for per ADC per UE info structure*/
	padc_ue = rte_zmalloc("adc ue info", sizeof(struct dp_adc_ue_info),
			RTE_CACHE_LINE_SIZE);
	if (padc_ue == NULL) {
		RTE_LOG(ERR, DP, "Failed to allocate memory for adc ue info");
		return ;
	}
	copy_dp_adc_rules(&padc_ue->adc_info, adc_info);

	RTE_LOG(DEBUG, DP, "ADC UE INFO ADD: ue_addr:"IPV4_ADDR ",",
					IPV4_ADDR_HOST_FORMAT(key.ue_ipv4));
	RTE_LOG(DEBUG, DP, "adc_id:%u\n",
					old->adc_rule_id[idx]);
	ret = rte_hash_add_key_data(rte_adc_ue_hash,
					&key, padc_ue);
	if (ret < 0)
			rte_panic("Failed to add entry in hash table");
}

/**
 * @brief Function to del adc entry with key and
 * update adc address and rating group.
 *
 */
static void
del_adc_entry_key_with_idx(struct ue_session_info *data, uint32_t idx)
{
	int ret;
	struct dl_bm_key key;
	struct dp_adc_ue_info *padc_ue;

	key.ue_ipv4 = data->ue_addr.u.ipv4_addr;
	key.rid = data->adc_rule_id[idx];

	if (key.rid == 0)
		return;

	RTE_LOG(DEBUG, DP, "ADC UE DEL:key: adc_id: %d, ue_addr:"IPV4_ADDR ",",
		key.rid, IPV4_ADDR_HOST_FORMAT(key.ue_ipv4));

	/* Get per ADC per UE info structure */
	ret = iface_lookup_adc_ue_data(&key, (void **)&padc_ue);
	if (ret < 0) {
	RTE_LOG(DEBUG, DP, "ADC UE DEL Fail !!:key: adc_id: %d, ue_addr:"IPV4_ADDR ",",
		key.rid, IPV4_ADDR_HOST_FORMAT(key.ue_ipv4));
		return ;
	}

	ret = rte_hash_del_key(rte_adc_ue_hash,
			&key);

	if (ret < 0)
		rte_panic("Failed to del entry from hash table");

	/* free the memory*/
	rte_free(padc_ue);
}

/**
 * @brief Check for change in adc rule.
 */
static void
update_adc_rules(struct ue_session_info *old,
			struct ue_session_info *new)
{
	uint32_t i;
	uint32_t *p1;
	uint32_t *p2;
	uint32_t n1;
	uint32_t n2;
	uint32_t n;

	/* Modify adc rule keys*/
	p1 = old->adc_rule_id;
	p2 = new->adc_rule_id;
	n1 = old->num_adc_rules;
	n2 = new->num_adc_rules;
	n = (n1 > n2) ? (n2) : (n1);
	for (i = 0; i < n; i++)
		if (p1[i] != p2[i]) {
			del_adc_entry_key_with_idx(old, i);
			add_adc_entry_key_with_idx(old, new, i);
		}

	if (n1 > n2)
		while (i < n1) {
			del_adc_entry_key_with_idx(old, i);
			i++;
		}
	else if (n1 < n2)
		while (i < n2) {
			add_adc_entry_key_with_idx(old, new, i);
			i++;
		}

	old->num_adc_rules = n2;
}

/******************** ADC SponsDNS Table **********************/
void print_adc_hash(void)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;

	printf("\nADC Hash table\n");

	while (rte_hash_iterate(rte_adc_hash, &next_key, &next_data, &iter) >= 0) {

		struct msg_adc *msg_adc = next_data;
		struct in_addr tmp_ip_key;

		memcpy(&tmp_ip_key, next_key, sizeof(struct in_addr));

		printf("%-15s ", inet_ntoa(tmp_ip_key));
		printf("%d ", msg_adc->rule_id);
	}
	puts("<\\ >\n");
}

int
adc_dns_entry_add(struct msg_adc *data)
{
	struct msg_adc *adc;
	uint32_t key32 = 0;
	int32_t ret;
	adc = rte_malloc("data", sizeof(struct msg_adc),
			RTE_CACHE_LINE_SIZE);
	if (adc == NULL){
		RTE_LOG(ERR, DP, "Failed to allocate memory");
		return -1;
	}
	*adc = *data;

	key32 = adc->ipv4;
	ret = rte_hash_add_key_data(rte_adc_hash, &key32,
			adc);
	if (ret < 0){
		RTE_LOG(ERR, DP, "Failed to add entry in hash table");
		return -1;
	}
	return 0;
}

int adc_dns_entry_delete(struct msg_adc *data)
{
	struct msg_adc *adc;
	uint32_t key32 = 0;
	int32_t ret;
	key32 = data->ipv4;
	ret = rte_hash_lookup_data(rte_adc_hash, &key32,
			(void **)&adc);
	if (ret < 0) {
		RTE_LOG(ERR, DP, "Failed to del\n"
				"adc key 0x%x to hash table\n",
				data->ipv4);
		return -1;
	}
	ret = rte_hash_del_key(rte_adc_hash, &key32);
	if (ret < 0){
		RTE_LOG(ERR, DP, "Failed to del entry in hash table");
		return -1;
	}
	rte_free(adc);
	return 0;
}

/******************** Session functions **********************/
/**
 * @brief Function to return session info entry address.
 *	if entry not found, allocate the memory & add entry.
 *
 */

static struct dp_session_info *
get_session_data(uint64_t sess_id, uint32_t is_mod)
{
	struct dp_session_info *data = NULL;
	int ret;
	/* check if session exists*/
	if (unlikely(rte_sess_hash == NULL))
	{
		static int show_message_once;
		if (show_message_once == 0) {
			RTE_LOG(NOTICE, DP, "Sess Hash Table not yet setup\n");
			show_message_once = 1;
		}
		return NULL;
	}

	rte_hash_lookup_data(rte_sess_hash, &sess_id, (void **)&data);

	if (data != NULL)
		return data;

	/* allocate memory only if request is from session create*/
	if (is_mod != SESS_CREATE)
		return NULL;

	/* allocate memory for session info*/
	data = rte_zmalloc("data", sizeof(struct dp_session_info),
			RTE_CACHE_LINE_SIZE);
	if (data == NULL){
		RTE_LOG(ERR, DP, "Failed to allocate memory for session info");
		return NULL;
	}

	/* add entry*/
	ret = rte_hash_add_key_data(rte_sess_hash, &sess_id, data);
	if (ret < 0){
		RTE_LOG(ERR, DP, "Failed to add entry in hash table");
		rte_free(data);
		return NULL;
	}

	return data;
}

int
dp_session_table_create(struct dp_id dp_id, uint32_t max_elements)
{
	RTE_SET_USED(dp_id);
	int rc;
	rc = hash_create(dp_id.name, &rte_sess_hash, max_elements * 4,
			sizeof(uint64_t));
	return rc;
}

int
dp_session_table_delete(struct dp_id dp_id)
{
	RTE_SET_USED(dp_id);
	rte_hash_free(rte_sess_hash);
	return 0;
}

static void
copy_session_info(struct dp_session_info *dst,
		struct session_info *src)
{
	int i;
	dst->ue_addr = src->ue_addr;
	dst->ul_s1_info = src->ul_s1_info;
	dst->dl_s1_info = src->dl_s1_info;
	dst->num_ul_pcc_rules = src->num_ul_pcc_rules;
	for (i = 0; i < dst->num_ul_pcc_rules; i++)
		dst->ul_pcc_rule_id[i] = src->ul_pcc_rule_id[i];
	dst->num_dl_pcc_rules = src->num_dl_pcc_rules;
	for (i = 0; i < dst->num_dl_pcc_rules; i++)
		dst->dl_pcc_rule_id[i] = src->dl_pcc_rule_id[i];
	dst->ipcan_dp_bearer_cdr = src->ipcan_dp_bearer_cdr;
	dst->sess_id = src->sess_id;
	dst->service_id = src->service_id;
	dst->apn_mtr_idx = src->apn_mtr_idx;
}

int
dp_session_create(struct dp_id dp_id,
		struct session_info *entry)
{

	int ret;
	int i;
	struct dp_session_info *data;
	struct dp_session_info new;
	struct ue_session_info *ue_data = NULL;
	uint32_t ue_sess_id = UE_SESS_ID(entry->sess_id);
	uint32_t bear_id = UE_BEAR_ID(entry->sess_id);
	RTE_SET_USED(dp_id);
	RTE_LOG(DEBUG, DP, "BEAR_SESS ADD:sess_id:%u, bear_id:%u\n",
			ue_sess_id, bear_id);

	if ((entry->num_ul_pcc_rules > MAX_PCC_RULES)
			|| (entry->num_dl_pcc_rules > MAX_PCC_RULES)) {
		RTE_LOG(ERR, DP, "Number of PCC rule exceeds max limit %d\n",
				MAX_PCC_RULES);
		return -1;
	}

	if (entry->num_adc_rules > MAX_ADC_RULES) {
		RTE_LOG(ERR, DP, "Number of ADC rule exceeds max limit %d\n",
				MAX_ADC_RULES);
		return -1;
	}

	data = get_session_data(entry->sess_id, SESS_CREATE);
	if (data == NULL) {
		RTE_LOG(ERR, DP, "Failed to allocate memory");
		return -1;
	}

	copy_session_info(data, entry);
	data->sess_id = ue_sess_id;
#ifdef IDX_LOOKUP
	lookup_ul[rbuf.msg_union.msg_ul.s1u_sgw_teid] = data1;
#else
	data->num_ul_pcc_rules = 0;
	data->num_dl_pcc_rules = 0;

	copy_session_info(&new, entry);

	ret = rte_hash_lookup_data(rte_ue_hash, &ue_sess_id, (void **)&ue_data);
	if ((ue_data == NULL) || (ret == -ENOENT)) {
		/* return if this is not a default bearer and ue_data not created.
		 * only default bearer can create ue_data.*/
		if (bear_id != DEFAULT_BEARER) {
			/* create req for dedicated bearer, but ue_data not created,
			 * this means default bearer is not created for this UE. Hence
			 * return error and free memory allocated for dedicated bearer.
			 */
			RTE_LOG(ERR, DP, "BEAR_SESS ADD Fail: Default bearer not found for sess_id:%u, bear_id:%u\n",
						ue_sess_id, bear_id);
			rte_hash_del_key(rte_sess_hash, &entry->sess_id);
			free(data);
			return 0;
		}
		/* add UE data*/
		ue_data = rte_zmalloc("ue sess info", sizeof(struct ue_session_info),
				RTE_CACHE_LINE_SIZE);
		if (ue_data == NULL)
			rte_panic("Failed to alloc mem for ue session");
		ret = rte_hash_add_key_data(rte_ue_hash, &ue_sess_id, ue_data);
		if (ret < 0) {
			rte_panic("Failed to add entry in hash table");
			return -1;
		}

		ue_data->ue_addr = data->ue_addr;
		ue_data->bearer_count = 1;

#ifdef APN_MTR
		mtr_cfg_entry(data->apn_mtr_idx, &ue_data->apn_mtr_obj);
		RTE_LOG(DEBUG, DP, "UE_SESS ADD:bear_count:%u, apn_mtr_idx%u, "
				"apn_obj:0x%"PRIx64"\n",
				ue_data->bearer_count, data->apn_mtr_idx,
				(uint64_t)&ue_data->apn_mtr_obj);
#endif	/* APN_MTR */
	} else {
		/* update UE data*/
		ue_data->bearer_count += 1;
		RTE_LOG(DEBUG, DP, "BEAR_SESS ADD:bear_id:%u, bear_count:%u,\n",
				bear_id, ue_data->bearer_count);
	}

#endif				/*IDX_LOOKUP */
	/* Update UE session info ptr */
	data->ue_info_ptr = ue_data;
	/* Update adc rules */
	if (entry->num_adc_rules) {
		struct ue_session_info new_ue_data;
		new_ue_data.num_adc_rules = entry->num_adc_rules;
		for (i = 0; i < new_ue_data.num_adc_rules; i++)
			new_ue_data.adc_rule_id[i] = entry->adc_rule_id[i];
		/* Update ADC rules addr*/
		update_adc_rules(ue_data, &new_ue_data);
	}
	/* Update PCC rules addr*/
	update_pcc_rules(data, &new);

	return 0;
}

int
dp_session_modify(struct dp_id dp_id,
		struct session_info *entry)
{
	struct dp_session_info *data;
	struct dp_session_info mod_data;
	int i;
	RTE_SET_USED(dp_id);

	if ((entry->num_ul_pcc_rules > MAX_PCC_RULES)
			|| (entry->num_dl_pcc_rules > MAX_PCC_RULES)) {
		RTE_LOG(ERR, DP, "Number of PCC rule exceeds max limit %d\n",
				MAX_PCC_RULES);
		return -1;
	}

	if (entry->num_adc_rules > MAX_ADC_RULES) {
		RTE_LOG(ERR, DP, "Number of ADC rule exceeds max limit %d\n",
				MAX_ADC_RULES);
		return -1;
	}

	data = get_session_data(entry->sess_id, SESS_MODIFY);
	if (data == NULL) {
		printf("Session id 0x%"PRIx64" not found\n", entry->sess_id);
		return -1;
	}

#ifdef IDX_LOOKUP
	lookup_ul[rbuf.msg_union.msg_ul.s1u_sgw_teid] = data1;
#else

	copy_session_info(&mod_data, entry);
	/* Update adc rules */
	if (entry->num_adc_rules) {
		struct ue_session_info new_ue_data;
		new_ue_data.num_adc_rules = entry->num_adc_rules;
		for (i = 0; i < new_ue_data.num_adc_rules; i++)
			new_ue_data.adc_rule_id[i] = entry->adc_rule_id[i];
		/* Update ADC rules addr*/
		update_adc_rules(data->ue_info_ptr, &new_ue_data);
	}

	/* Update PCC rules addr*/
	update_pcc_rules(data, &mod_data);

	/* Copy dl information */
	struct dl_s1_info *dl_info;
	dl_info = &data->dl_s1_info;
	*dl_info = mod_data.dl_s1_info;

#endif				/*IDX_LOOKUP */
	return 0;
}
/**
 * Flush CDR records of all the PCC rules for the given Bearer session,
 * into cdr cvs record file.
 * @param session
 *	dp bearer session.
 *
 * @return
 * Void
 */

static void
flush_session_pcc_records(struct dp_session_info *session)
{
	uint32_t i;
	struct dp_pcc_rules *pcc_info;
	struct ul_bm_key ul_key;
	struct dl_bm_key dl_key;
	struct dp_sdf_per_bearer_info *psdf = NULL;

	RTE_LOG(DEBUG, DP, "Flushing PCC CDRs for session id 0x%"PRIx64": ebi %d @ "IPV4_ADDR"\n",
			session->sess_id, (uint8_t)UE_BEAR_ID(session->sess_id),
			IPV4_ADDR_HOST_FORMAT(session->ue_addr.u.ipv4_addr));
	dl_key.ue_ipv4 = session->ue_addr.u.ipv4_addr;
	for (i = 0; i < session->num_dl_pcc_rules; i++) {
		dl_key.rid = session->dl_pcc_rule_id[i];
		if ((rte_hash_lookup_data(rte_downlink_hash, &dl_key, (void **)&psdf)) < 0)
			continue;
		export_session_pcc_record(&psdf->pcc_info, &psdf->sdf_cdr, session);
	}

	ul_key.s1u_sgw_teid = session->ul_s1_info.sgw_teid;
	for (i = 0; i < session->num_ul_pcc_rules; i++) {
		ul_key.rid = session->ul_pcc_rule_id[i];
		if ((rte_hash_lookup_data(rte_uplink_hash, &ul_key, (void **)&psdf)) < 0)
			continue;
		export_session_pcc_record(&psdf->pcc_info, &psdf->sdf_cdr, session);
	}
}

/**
 * Flush CDR records of all the ADC rules for the given Bearer session,
 * into cdr cvs record file.
 * @param session
 *	dp bearer session.
 *
 * @return
 * Void
 */

static void
flush_session_adc_records(struct dp_session_info *session)
{
	uint32_t i;
	uint64_t m;
	uint32_t adc_id;
	struct adc_rules *adc_info;
	struct ipcan_dp_bearer_cdr adc_cdr;
	struct dl_bm_key key;
	struct dp_adc_ue_info *adc_ue_info;

	RTE_LOG(DEBUG, DP, "Flushing CDRs for session id 0x%"PRIx64": ebi %d @ "IPV4_ADDR"\n",
			session->sess_id, (uint8_t)UE_BEAR_ID(session->sess_id),
			IPV4_ADDR_HOST_FORMAT(session->ue_addr.u.ipv4_addr));

	key.ue_ipv4 = session->ue_addr.u.ipv4_addr;
	for (i = 0; i < session->ue_info_ptr->num_adc_rules; i++) {
		adc_id = session->ue_info_ptr->adc_rule_id[i];
		m = 1;
		adc_rule_info_get(&adc_id, 1, &m, (void **)&adc_info);

		key.rid = adc_id;
		if ((rte_hash_lookup_data(rte_adc_ue_hash, &key, (void **)&adc_ue_info)) < 0)
			continue;
		export_session_adc_record(adc_info, &adc_ue_info->adc_cdr, session);
	}
}

int
dp_session_delete(struct dp_id dp_id,
		struct session_info *entry)
{
	struct dp_session_info *data;
	RTE_SET_USED(dp_id);
	data = get_session_data(entry->sess_id, SESS_MODIFY);
	if (data == NULL) {
		printf("Session id 0x%"PRIx64" not found\n", entry->sess_id);
		return -1;
	}
#ifdef ADC_UPFRONT
	flush_session_adc_records(data);
#endif
	flush_session_pcc_records(data);

#ifdef IDX_LOOKUP
	lookup_ul[rbuf.msg_union.msg_ul.s1u_sgw_teid] = data1;
#else
	struct dp_session_info new;

	memset(&new, 0, sizeof(struct dp_session_info));
	/* Update PCC rules addr*/
	update_pcc_rules(data, &new);
	/* Update adc rules */
	if (data->ue_info_ptr->num_adc_rules) {
		struct ue_session_info new_ue_data = {0};
		/* Update ADC rules addr*/
		update_adc_rules(data->ue_info_ptr, &new_ue_data);
	}

	/* remove entry from session hash table*/
	if (rte_hash_del_key(rte_sess_hash, &entry->sess_id) < 0)
		return -1;
	rte_free(data);
#endif				/*IDX_LOOKUP */
	return 0;
}

/******************** Call back functions for Bearer Session ******************/
/**
 *  Call back to parse msg to create bearer session table
 *
 * @param
 *	msg_payload - payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_session_table_create(struct msgbuf *msg_payload)
{
	return session_table_create(msg_payload->dp_id,
			msg_payload->msg_union.msg_table.max_elements);
}

/**
 *  Call back to parse msg to delete table
 *
 * @param
 *	msg_payload - payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_session_table_delete(struct msgbuf *msg_payload)
{
	return session_table_delete(msg_payload->dp_id);
}

/**
 *  Call back to parse msg to add bearer session
 *
 * @param
 *	msg_payload - payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_session_create(struct msgbuf *msg_payload)
{
	return session_create(msg_payload->dp_id,
			msg_payload->msg_union.sess_entry);
}

/**
 *  Call back to parse msg to add bearer session
 *
 * @param
 *	msg_payload - payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_session_modify(struct msgbuf *msg_payload)
{
	return session_modify(msg_payload->dp_id,
			msg_payload->msg_union.sess_entry);
}

/**
 * Call back to delete bearer session.
 *
 * @param
 *	msg_payload - payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_session_delete(struct msgbuf *msg_payload)
{
	return session_delete(msg_payload->dp_id,
			msg_payload->msg_union.sess_entry);
}

/**
 * Initialization of Session Table Callback functions.
 */
void
app_sess_tbl_init(void)
{
	/* register msg type in DB*/
	iface_ipc_register_msg_cb(MSG_SESS_TBL_CRE, cb_session_table_create);
	iface_ipc_register_msg_cb(MSG_SESS_TBL_DES, cb_session_table_delete);
	iface_ipc_register_msg_cb(MSG_SESS_CRE, cb_session_create);
	iface_ipc_register_msg_cb(MSG_SESS_MOD, cb_session_modify);
	iface_ipc_register_msg_cb(MSG_SESS_DEL, cb_session_delete);
}

