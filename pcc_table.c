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

#include <rte_mbuf.h>

#include "vepc_cp_dp_api.h"
#include "main.h"
#include "util.h"
#include "acl.h"
#include "meter.h"
#include "interface.h"

struct rte_hash *rte_pcc_hash;
/**
 * @brief Called by DP to lookup key-value in PCC table.
 *
 * This function is thread safe (Read Only).
 */
int iface_lookup_pcc_data(const uint32_t key32,
					struct dp_pcc_rules **value)
{
	return rte_hash_lookup_data(rte_pcc_hash, &key32, (void **)value);
}

int
dp_pcc_table_create(struct dp_id dp_id, uint32_t max_elements)
{
	return hash_create(dp_id.name, &rte_pcc_hash, max_elements * 4,
				   sizeof(uint32_t));
}

int
dp_pcc_table_delete(struct dp_id dp_id)
{
	RTE_SET_USED(dp_id);
	rte_hash_free(rte_pcc_hash);
	return 0;
}

int
dp_pcc_entry_add(struct dp_id dp_id, struct pcc_rules *entry)
{
	struct dp_pcc_rules *pcc;
	uint32_t key32;
	int ret;
	void *mtr_obj;

	pcc = rte_zmalloc("data", sizeof(struct dp_pcc_rules),
			   RTE_CACHE_LINE_SIZE);
	if (pcc == NULL)
		return -1;
	memcpy(pcc, entry, sizeof(struct pcc_rules));

	key32 = entry->rule_id;
	ret = rte_hash_add_key_data(rte_pcc_hash, &key32,
				  pcc);
	if (ret < 0) {
		RTE_LOG(ERR, DP, "Failed to add entry in hash table");
		return -1;
	}

	RTE_LOG(DEBUG, DP, "PCC_TBL ADD: rule_id:%u, addr:0x%"PRIx64
			", mtr_idx:%u\n",
			pcc->rule_id, (uint64_t)pcc, pcc->mtr_profile_index);
	return 0;
}
int
dp_pcc_entry_delete(struct dp_id dp_id, struct pcc_rules *entry)
{
	struct dp_pcc_rules *pcc;
	uint32_t key32;
	int ret;
	key32 = entry->rule_id;
	ret = rte_hash_lookup_data(rte_pcc_hash, &key32,
				  (void **)&pcc);
	if (ret < 0) {
		RTE_LOG(ERR, DP, "Failed to del\n"
			"pcc key 0x%x to hash table\n",
			 key32);
		return -1;
	}
	ret = rte_hash_del_key(rte_pcc_hash, &key32);
	if (ret < 0)
		return -1;
	rte_free(pcc);
	return 0;
}

/******************** Call back functions **********************/
/**
 *  Call back to parse msg to create pcc rules table
 *
 * @param msg_payload
 *	payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_pcc_table_create(struct msgbuf *msg_payload)
{
	return pcc_table_create(msg_payload->dp_id,
				msg_payload->msg_union.msg_table.max_elements);
}

/**
 *  Call back to parse msg to delete table
 *
 * @param msg_payload
 *	payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_pcc_table_delete(struct msgbuf *msg_payload)
{
	return pcc_table_delete(msg_payload->dp_id);
}

/**
 *  Call back to parse msg to add pcc rules.
 *
 * @param msg_payload
 *	payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_pcc_entry_add(struct msgbuf *msg_payload)
{
	return pcc_entry_add(msg_payload->dp_id,
					msg_payload->msg_union.pcc_entry);
}

/**
 * Call back to delete pcc rules.
 * @param msg_payload
 *	payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_pcc_entry_delete(struct msgbuf *msg_payload)
{
	return pcc_entry_delete(msg_payload->dp_id,
					msg_payload->msg_union.pcc_entry);
}

/**
 * Initialization of PCC Table Callback functions.
 */
void app_pcc_tbl_init(void)
{
	/* register msg type in DB*/
	iface_ipc_register_msg_cb(MSG_PCC_TBL_CRE, cb_pcc_table_create);
	iface_ipc_register_msg_cb(MSG_PCC_TBL_DES, cb_pcc_table_delete);
	iface_ipc_register_msg_cb(MSG_PCC_TBL_ADD, cb_pcc_entry_add);
	iface_ipc_register_msg_cb(MSG_PCC_TBL_DEL, cb_pcc_entry_delete);
}

