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

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>

#include "main.h"
#include "meter.h"
#include "interface.h"

#define APP_PKT_FLOW_POS                33
#define APP_PKT_COLOR_DSCP              15
#define APP_PKT_COLOR_DSTIP_LB         33
#define APP_PKT_COLOR_POS              APP_PKT_COLOR_DSCP

#if APP_PKT_FLOW_POS > 64 || APP_PKT_COLOR_POS > 64
#error Byte offset needs to be less than equal to 64
#endif
/** Traffic metering configuration */
#define APP_MODE_FWD                    0
#define APP_MODE_SRTCM_COLOR_BLIND      1
#define APP_MODE_SRTCM_COLOR_AWARE      2
#define APP_MODE_TRTCM_COLOR_BLIND      3
#define APP_MODE_TRTCM_COLOR_AWARE      4

#define APP_MODE	APP_MODE_SRTCM_COLOR_BLIND

#if APP_MODE == APP_MODE_FWD

#define FUNC_METER(a, b, c, d) (color, flow_id = flow_id,\
			pkt_len = pkt_len, time = time)
#define FUNC_CONFIG(a, b)
#define PARAMS	app_srtcm_params
#define FLOW_METER int

#elif APP_MODE == APP_MODE_SRTCM_COLOR_BLIND

#define FUNC_METER(a, b, c, d) rte_meter_srtcm_color_blind_check(a, b, c)
#define FUNC_CONFIG   rte_meter_srtcm_config
#define PARAMS        app_srtcm_params
#define PARAMS_AMBR   ambr_srtcm_params
#define FLOW_METER    struct rte_meter_srtcm

#elif (APP_MODE == APP_MODE_SRTCM_COLOR_AWARE)

#define FUNC_METER    rte_meter_srtcm_color_aware_check
#define FUNC_CONFIG   rte_meter_srtcm_config
#define PARAMS        app_srtcm_params
#define PARAMS_AMBR   ambr_srtcm_params
#define FLOW_METER    struct rte_meter_srtcm

#elif (APP_MODE == APP_MODE_TRTCM_COLOR_BLIND)

#define FUNC_METER(a, b, c, d) rte_meter_trtcm_color_blind_check(a, b, c)
#define FUNC_CONFIG  rte_meter_trtcm_config
#define PARAMS       app_trtcm_params
#define PARAMS_AMBR   ambr_trtcm_params
#define FLOW_METER   struct rte_meter_trtcm

#elif (APP_MODE == APP_MODE_TRTCM_COLOR_AWARE)

#define FUNC_METER   rte_meter_trtcm_color_aware_check
#define FUNC_CONFIG  rte_meter_trtcm_config
#define PARAMS       app_trtcm_params
#define PARAMS_AMBR   ambr_trtcm_params
#define FLOW_METER   struct rte_meter_trtcm

#else
#error Invalid value for APP_MODE
#endif

enum policer_action {
	GREEN = e_RTE_METER_GREEN,
	YELLOW = e_RTE_METER_YELLOW,
	RED = e_RTE_METER_RED,
	DROP = 3,
};
struct mtr_table {
	char name[MAX_LEN];
	struct rte_meter_srtcm_params *params;
	uint16_t num_entries;
	uint16_t max_entries;
};

static enum policer_action policer_table[e_RTE_METER_COLORS][e_RTE_METER_COLORS] = {
	{GREEN, RED, RED},
	{DROP, YELLOW, RED},
	{DROP, DROP, RED}
};

static const char *colorstr[] = { "GREEN", "YELLOW", "RED", "DROP" };

struct mtr_table mtr_profile_tbl;
FLOW_METER *app_flows;
FLOW_METER *ambr_flows;

/**
 * Function to set color.
 * @return
 *	None
 */
static inline void
app_set_pkt_color(uint8_t *pkt_data, enum policer_action color)
{
	pkt_data[APP_PKT_COLOR_POS] = (uint8_t) color;
}

/**
 * Process the packet to get action
 *
 * @param pkt
 *	mbuf pointer
 * @param time
 * @param m
 *	srtcm context
 *
 * @return
 *	int - action to be performed on the packet
 */
static int
app_pkt_handle(struct rte_meter_srtcm *m, struct rte_mbuf *pkt,
				uint64_t time)
{
	uint8_t input_color, output_color;
	uint8_t *pkt_data = rte_pktmbuf_mtod(pkt, uint8_t *);
	uint32_t pkt_len = rte_pktmbuf_pkt_len(pkt) - sizeof(struct ether_hdr);
	enum policer_action action;

	input_color = pkt_data[APP_PKT_COLOR_POS] & 0x3;
	/* color input is not used for blind modes */
	output_color =
		(uint8_t) FUNC_METER(m,
				 time,
				 pkt_len,
				 (enum rte_meter_color)input_color);

	/* Apply policing and set the output color */
	action = policer_table[input_color][output_color];

	app_set_pkt_color(pkt_data, action);

	return action;
}

/******************************************************************************/
/**
 * Create meter param table.
 * @param table_name
 *	table name
 * @param max_entries
 *	max entries in table.
 *
 * @return
 *	None
 */
static void
mtr_table_create(struct mtr_table *mtr_tbl,
			const char *table_name, uint32_t max_entries)
{

	mtr_tbl->num_entries = 0;
	mtr_tbl->max_entries = max_entries;
	strncpy(mtr_tbl->name, table_name, MAX_LEN);
	mtr_tbl->params = rte_zmalloc("params",
			sizeof(struct rte_meter_srtcm_params) * max_entries,
			RTE_CACHE_LINE_SIZE);
	if (mtr_tbl->params == NULL)
		rte_panic("Meter table memory alloc fail");
	RTE_LOG(INFO, DP, "Meter table: %s created\n", mtr_tbl->name);
}

/**
 * Destroy meter table.
 *
 * @param mtr_tbl
 *	meter table.
 *
 * @return
 *	None
 */
static void
mtr_table_destroy(struct mtr_table *mtr_tbl)
{
	rte_free(mtr_tbl->params);
	RTE_LOG(INFO, DP, "Meter table: %s destroyed\n", mtr_tbl->name);
	memset(mtr_tbl, 0, sizeof(struct mtr_table));
}

/**
 * Add entry in meter param table.
 *
 * @param mtr_tbl
 *	meter table.
 * @param mtr_profile_index
 *	meter profile index
 * @param mtr_param
 *	meter parameters.
 *
 * @return
 *	None
 */
static void
mtr_add_entry(struct mtr_table *mtr_tbl,
		uint16_t mtr_profile_index, struct mtr_params *mtr_param)
{
	struct rte_meter_srtcm_params *app_srtcm_params;

	if (mtr_tbl->num_entries == mtr_tbl->max_entries) {
		printf("MTR: Max entries reached\n");
		return;
	}
	if (mtr_profile_index >= mtr_tbl->max_entries) {
		printf("MTR: profile id greater than max entries\n");
		return;
	}

	app_srtcm_params = &mtr_tbl->params[mtr_profile_index];
	app_srtcm_params->cir = mtr_param->cir;
	app_srtcm_params->cbs = mtr_param->cbs;
	app_srtcm_params->ebs = mtr_param->ebs;
	mtr_tbl->num_entries++;
	RTE_LOG(INFO, DP, "MTR_PROFILE ADD: index %d cir:%lu, cbd:%lu, ebs:%lu\n",
			mtr_profile_index, app_srtcm_params->cir,
			app_srtcm_params->cbs, app_srtcm_params->ebs);
}

/**
 * Delete entry from meter table.
 *
 * @param mtr_tbl
 *	meter table.
 * @param mtr_profile_index
 *	meter profile index
 *
 * @return
 *	None
 */
static void
mtr_del_entry(struct mtr_table *mtr_tbl, uint16_t mtr_profile_index)
{
	struct rte_meter_srtcm_params *app_srtcm_params;

	if (mtr_profile_index >= mtr_tbl->max_entries) {
		printf("MTR: profile id greater than max entries\n");
		return;
	}

	app_srtcm_params = &mtr_tbl->params[mtr_profile_index];
	app_srtcm_params->cir = 0;
	app_srtcm_params->cbs = 0;
	app_srtcm_params->ebs = 0;
	mtr_tbl->num_entries--;
}

int
mtr_cfg_entry(int msg_id, void *msg_payload)
{
	struct rte_meter_srtcm *m;
	struct mtr_table *mtr_tbl = &mtr_profile_tbl;
	m = (struct rte_meter_srtcm *)msg_payload;
	/* NOTE: rte_malloc will be replaced by simple ring_alloc in future*/

	rte_meter_srtcm_config(m, &mtr_tbl->params[msg_id]);

	if ((m)->cir_period == 0)
		rte_exit(EXIT_FAILURE, "Meter config fail. cir_period is 0!!");
	return 0;
}

int
mtr_process_pkt(void **mtr_id, uint64_t **mtr_drp, struct rte_mbuf **pkt,
						uint32_t n, uint64_t *pkts_mask)
{
	uint64_t current_time;
	struct rte_meter_srtcm *m;
	uint32_t i;
	for (i = 0; i < n; i++) {
		if (!ISSET_BIT(*pkts_mask, i))
			continue;
		if (mtr_id[i] == NULL)
			continue;
		m = (struct rte_meter_srtcm *)mtr_id[i];
		current_time = rte_rdtsc();
		if (m == NULL) {
			RTE_LOG(DEBUG, DP, "MTR not found!!!\n");
			continue;
		}
		if ((app_pkt_handle(m, pkt[i], current_time) == RED)
			|| (app_pkt_handle(m, pkt[i], current_time) == DROP))
			RESET_BIT(*pkts_mask, i);
			*mtr_drp[i]++;
	}
	return 0;
}

int
dp_meter_profile_table_create(struct dp_id dp_id, uint32_t max_elements)
{
	mtr_table_create(&mtr_profile_tbl, dp_id.name, max_elements);
	return 0;
}

int
dp_meter_profile_table_delete(struct dp_id dp_id)
{
	mtr_table_destroy(&mtr_profile_tbl);
	return 0;
}

int
dp_meter_profile_entry_add(struct dp_id dp_id, struct mtr_entry *entry)
{
	mtr_add_entry(&mtr_profile_tbl,
			entry->mtr_profile_index, &entry->mtr_param);
	return 0;
}

int
dp_meter_profile_entry_delete(struct dp_id dp_id, struct mtr_entry *entry)
{
	mtr_del_entry(&mtr_profile_tbl, entry->mtr_profile_index);
	return 0;
}


/******************** Call back functions **********************/
/**
 *  Call back to parse msg to create meter rules table
 *
 * @param msg_payload
 *	payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_meter_profile_table_create(struct msgbuf *msg_payload)
{
	return meter_profile_table_create(msg_payload->dp_id,
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
cb_meter_profile_table_delete(struct msgbuf *msg_payload)
{
	return meter_profile_table_delete(msg_payload->dp_id);
}

/**
 *  Call back to parse msg to add meter rules
 *
 * @param msg_payload
 *	payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_meter_profile_entry_add(struct msgbuf *msg_payload)
{
	return meter_profile_entry_add(msg_payload->dp_id,
					msg_payload->msg_union.mtr_entry);
}

/**
 * Delete meter rules.
 *
 * @param msg_payload
 *	payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_meter_profile_entry_delete(struct msgbuf *msg_payload)
{
	return meter_profile_entry_delete(msg_payload->dp_id,
					msg_payload->msg_union.mtr_entry);
}

/**
 * Initialization of Meter Table Callback functions.
 */
void app_mtr_tbl_init(void)
{
	/* register msg type in DB*/
	iface_ipc_register_msg_cb(MSG_MTR_CRE, cb_meter_profile_table_create);
	iface_ipc_register_msg_cb(MSG_MTR_DES, cb_meter_profile_table_delete);
	iface_ipc_register_msg_cb(MSG_MTR_ADD, cb_meter_profile_entry_add);
	iface_ipc_register_msg_cb(MSG_MTR_DEL, cb_meter_profile_entry_delete);
}

