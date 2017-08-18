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

#ifndef _MAIN_H_
#define _MAIN_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of dataplane initialization, user session
 * and rating group processing functions.
 */
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_meter.h>

#include "epc_packet_framework.h"
#include "vepc_cp_dp_api.h"
#include "dp_ipc_api.h"

/**
 * dataplane rte logs.
 */
#define RTE_LOGTYPE_DP	RTE_LOGTYPE_USER1

/**
 * CP DP communication API rte logs.
 */
#define RTE_LOGTYPE_API   RTE_LOGTYPE_USER2

/**
 * rte notification log level.
 */
#define NOTICE 0

/**
 * rte information log level.
 */
#define INFO 1

/**
 * rte debug log level.
 */
#define DEBUG 2

/**
 * max prefetch.
 */
#define PREFETCH_OFFSET	8
/**
 * reset nth bit.
 */
#define SET_BIT(mask, n)  ((mask) |= (1LLU << (n)))

/**
 * reset nth bit.
 */
#define RESET_BIT(mask, n)  ((mask) &= ~(1LLU << (n)))

/**
 * check if nth bit is set.
 */
#define ISSET_BIT(mask, n)  (((mask) & (1LLU << (n))) ? 1 : 0)

/**
 * default ring size
 */
#define EPC_DEFAULT_RING_SZ	4096

/**
 * default burst size
 */
#define EPC_DEFAULT_BURST_SZ	32

/**
 * burst size of 64 pkts
 */
#define EPC_BURST_SZ_64		64

/**
 * max burst size
 */
#define MAX_BURST_SZ EPC_BURST_SZ_64
/**
 * Reserved ADC ruleids installed by DP during init.
 * example: DNS_RULE_ID to identify dns pkts. .
 */
#define RESVD_IDS 1

/**
 * Pre-defined DNS sdf filter rule id.
 */
#define DNS_RULE_ID (MAX_ADC_RULES + 1)

/**
 * max length of name string.
 */
#define MAX_LEN 128

/**
 * uplink flow.
 */
#define UL_FLOW 1

/**
 * downlink flow.
 */
#define DL_FLOW 2

/**
 * offset of meta data in headroom.
 */
#define META_DATA_OFFSET 128

/**
 * max records charging.
 */
#define MAX_SESSION_RECS  64

/**
 * Set DPN ID
 */
#define DPN_ID			(12345)

/**
 * Application configure structure .
 */
struct app_params {
	uint32_t s1u_ip;			/* s1u ipv4 address */
	uint32_t sgi_ip;			/* sgi ipv4 address */
	uint32_t s1u_port;			/* port no. to act as s1u */
	uint32_t sgi_port;			/* port no. to act as sgi */
	uint32_t log_level;			/* log level default - INFO,
						 * 1 - DEBUG	 */
	struct ether_addr s1u_ether_addr;	/* s1u mac addr */
	struct ether_addr sgi_ether_addr;	/* sgi mac addr */
	struct ether_addr enb_ether_addr;	/* enodeB mac addr */
	struct ether_addr as_ether_addr;	/* app server mac addr */
};
/** extern the app config struct */
extern struct app_params app;

/** ethernet addresses of ports */
struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

/** ethernet addresses of ports */
extern struct ether_addr ports_eth_addr[];

/** ADC sponsored dns table msg payload */
struct msg_adc {
	uint32_t ipv4;
	uint32_t rule_id;
};

/** UL Bearer Map key for hash lookup.*/
struct ul_bm_key {
	/** s1u teid */
	uint32_t s1u_sgw_teid;
	/** rule id*/
	uint32_t rid;
};

/** CDR actions, N_A should never be accounted for */
enum pkt_action_t {CHARGED, DROPPED, N_A};
/**
 * Dataplane Application Detection and Control Rule structure.
 * This structure contains only parameters which are updated or refered
 * by dataplane. Fields which are common are removed to reduce struct size.
 * For complete information about ADC rule please refer
 * "struct adc_rules"
 */
struct dp_adc_rules {
	enum selector_type sel_type;	/* domain name, IP addr
					 * or IP addr prefix*/
	uint32_t rule_id;				/* Rule ID*/
	uint32_t rating_group;			/* Rating of Group*/
	uint8_t  gate_status;			/* Open/close*/
	uint8_t  report_level;			/* Report Level*/
	uint8_t  mute_notify;			/* Mute on/off*/
	struct tm rule_activation_time;		/* Rule Start time*/
	struct tm rule_deactivation_time;	/* Rule Stop time*/
	struct  redirect_info redirect_info;	/* Redirect  info*/
	uint64_t drop_pkt_count;		/* No. of pkts dropped */
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));
/**
 * Policy and Charging Control structure for DP
 */
struct dp_pcc_rules {
	uint32_t rule_id;
	char rule_name[MAX_LEN];		/**< Rule Name */
	uint32_t rating_group;			/**< Group rating */
	uint32_t service_id;			/**< Service ID */
	uint8_t rule_status;			/**< Rule Status */
	uint8_t  gate_status;			/**< Gating open/close */
	uint8_t  session_cont;			/**< Total Session Count */
	uint8_t  report_level;			/**< Level of report */
	uint8_t  charging_mode;			/**< Charging mode */
	uint8_t  metering_method;		/**< Metering Methods
						 * -fwd, srtcm, trtcm */
	uint8_t  mute_notify;			/**< Mute on/off*/
	uint32_t  monitoring_key;		/**< key to identify monitor
						 * control instance */
	char sponsor_id[MAX_LEN];		/**< Sponsor ID*/
	struct  redirect_info redirect_info;	/**< Redirect  info*/
	uint32_t precedence;			/**< Precedence*/
	uint32_t mtr_profile_index;		/**< Meter profile index*/
	uint64_t drop_pkt_count;		/**< Drop count*/
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));


/**
 * Bearer Session information structure
 */
struct dp_session_info {
	struct ip_addr ue_addr;				/**< UE ip address*/
	struct ul_s1_info ul_s1_info;			/**< UpLink S1u info*/
	struct dl_s1_info dl_s1_info;			/**< DownLink S1u info*/
	uint8_t linked_bearer_id;				/**< Linked EPS Bearer ID (LBI)*/

	/* PCC rules related params*/
	uint32_t num_ul_pcc_rules;			/**< No. of UL PCC rule*/
	uint32_t ul_pcc_rule_id[MAX_PCC_RULES];		/**< PCC rule id supported in UL*/
	uint32_t num_dl_pcc_rules;			/**< No. of PCC rule*/
	uint32_t dl_pcc_rule_id[MAX_PCC_RULES];		/**< PCC rule id*/

	/* Charging Data Records*/
	struct ipcan_dp_bearer_cdr ipcan_dp_bearer_cdr;	/**< IP CAN bearer CDR*/

	uint64_t sess_id;						/**< session id of this bearer
									 * last 4 bits of sess_id
									 * maps to bearer id*/
	uint32_t service_id;						/**< Type of service given
									 * to this session like
									 * Internet, Management, CIPA etc
									 */
	uint32_t apn_mtr_idx;			/**< APN meter profile index*/

	struct ue_session_info *ue_info_ptr;	/**< Pointer to UE info of this bearer */
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * UE Session information structure
 */
struct ue_session_info {
	struct ip_addr ue_addr;			/**< UE ip address*/
	uint32_t bearer_count;			/**< Num. of bearers configured*/
	struct rte_meter_srtcm apn_mtr_obj;			/**< APN meter object pointer*/

	/* rating groups CDRs*/
	struct rating_group_index_map rg_idx_map[MAX_RATING_GRP]; /**< Rating group index*/
	struct ipcan_dp_bearer_cdr rating_grp[MAX_RATING_GRP];	/**< rating groups CDRs*/
	uint64_t apn_mtr_drops;								/**< drop count due to apn metering*/

	/* ADC rules related params*/
	uint32_t num_adc_rules;					/**< No. of ADC rule*/
	uint32_t adc_rule_id[MAX_ADC_RULES]; 	/**< list of ADC rule id*/
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * SDF and Bearer specific information structure
 */
struct dp_sdf_per_bearer_info {
	struct dp_pcc_rules pcc_info;						/**< PCC info of this bearer */
	struct rte_meter_srtcm sdf_mtr_obj;					/**< meter object for this SDF flow */
	struct ipcan_dp_bearer_cdr sdf_cdr;					/**< per SDF bearer CDR*/
	struct dp_session_info *bear_sess_info;  	/**< pointer to bearer this flow belongs to */
	uint64_t sdf_mtr_drops;								/**< drop count due to sdf metering*/
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * per ADC, UE information structure
 */
struct dp_adc_ue_info {
	struct dp_adc_rules adc_info;						/**< ADC info of this bearer */
	struct ipcan_dp_bearer_cdr adc_cdr;				/**< per ADC bearer CDR*/
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

#ifdef INSTMNT
extern uint32_t flag_wrkr_update_diff;
extern uint64_t total_wrkr_pkts_processed;
#endif				/* INSTMNT */

extern int arp_icmp_get_dest_mac_address(const uint32_t ipaddr,
		const uint32_t phy_port,
		struct ether_addr *hw_addr,
		uint32_t *nhip);

/**
 * Push DNS packets to DN queue from worker cores
 *
 * @param pkt
 *	pkt - DNS packet.
 *
 * @return
 *	0  on success
 *	-1 on failure
*/
int
push_dns_ring(struct rte_mbuf *);

/**
 * Pop DNS packets from ring and send to library for processing
 *
 * @param
 *  Unused
 *
 * @return
 *	None
 */
void
scan_dns_ring(__rte_unused void *args);

/**
 * Function to Initialize the Environment Abstraction Layer (EAL).
 *
 * @param void
 *	void.
 *
 * @return
 *	None
 */
void
dp_port_init(void);

/**
 * Function to initialize the dataplane application config.
 *
 * @param argc
 *	number of arguments.
 * @param argv
 *	list of arguments.
 *
 * @return
 *	None
 */
void
dp_init(int argc, char **argv);

/**
 * Decap gtpu header.
 *
 * @param pkts
 *	pointer to mbuf of incoming packets.
 * @param n
 *	number of pkts.
 * @param pkts_mask
 * 	bit mask to process the pkts, reset bit to free the pkt.
 */
void
gtpu_decap(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask);

/**
 * Encap gtpu header.
 *
 * @param sess_info
 *	pointer to session info.
 * @param pkts
 *	pointer to mbuf of incoming packets.
 * @param n
 *	number of pkts.
 * @param pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 */
void
gtpu_encap(void **sess_info, struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask);

/**
 * Function to handle incoming pkts on s1u interface.
 *
 * @param p
 *	pointer to pipeline.
 * @param pkts
 *	pointer to pkts.
 * @param n
 *	number of pkts.
 *
 * @return
 *	- 0  on success
 *	- -1 on failure
 */
int
s1u_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n);

/**
 * Function to handle incoming pkts on sgi interface.
 *
 * @param p
 *	pointer to pipeline.
 * @param pkts
 *	pointer to pkts.
 * @param n
 *	number of pkts.
 *
 * @return
 *	- 0  on success
 *	- -1 on failure
 */
int
sgi_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n);

/**
 * Clone the DNS pkts and send to CP.
 * @param pkts
 *	pointer to mbuf of incoming packets.
 * @param n
 *	number of pkts.
 */
void
clone_dns_pkts(struct rte_mbuf **pkts, uint32_t n, uint64_t pkts_mask);

/**
 * If rule id is DNS, update the meta info.
 * @param pkts
 *	pointer to mbuf of incoming packets.
 * @param n
 *	number of pkts.
 * @param rid
 *	sdf rule id to check the DNS pkts.
 */
void
update_dns_meta(struct rte_mbuf **pkts, uint32_t n, uint32_t *rid);

/**
 * Set checksum offload in meta,
 * Fwd based on nexthop info.
 * @param pkts
 *	pointer to mbuf of incoming packets.
 * @param n
 *	number of pkts.
 * @param pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param portid
 *	port id to forward the pkt.
 */
void
update_nexthop_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint8_t portid);

/************* ADC Rule Table function prototype***********/
/**
 * Given the ADC UE info struct, retrieve the ADC info.
 * @param pkts
 *	pointer to mbuf of incoming packets.
 * @param n
 *	number of pkts.
 * @param res
 *	list of adc rule ids, retrieved from adc filters.
 * @param adc_ue_info
 *	list of adc ue information structs to be returned.
 * @param flow
 *	this variable tells the caller is from UL_FLOW or DL_FLOW.
 *
 * @return
 * Void
 */
void
adc_ue_info_get(struct rte_mbuf **pkts, uint32_t n, uint32_t *res,
		void **adc_ue_info, uint32_t flow);

/**
 * Gate based on ADC filter entry.
 * @param rid
 *	ADC rule id.
 * @param adc_info
 *	ADC information.
 * @param  n
 *	num. of rule ids.
 * @param  adc_pkts_mask
 *	bit mask is set if adc rule is hit and gate is open.
 * @param  pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 *
 * @return
 * Void
 */
void
adc_gating(uint32_t *rid, void **adc_info, uint32_t n,
			uint64_t *adc_pkts_mask, uint64_t *pkts_mask);

/************* Session information function prototype***********/
/**
 * Get the UL session info from table lookup.
 * @param pkts
 *	pointer to mbuf of incoming packets.
 * @param n
 *	number of pkts.
 * @param res
 *	pointer to results of acl lookup.
 * @param pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param sess_info
 *	session information returned after hash lookup.
 */
void
ul_sess_info_get(struct rte_mbuf **pkts, uint32_t n, uint32_t *res,
		uint64_t *pkts_mask, void **sess_info);
/**
 * Get the DL session info from table lookup.
 * @param pkts
 *	pointer to mbuf of incoming packets.
 * @param n
 *	number of pkts.
 * @param res
 *	pointer to results of acl lookup.
 * @param pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param sess_info
 *	session information returned after hash lookup.
 */
void
dl_sess_info_get(struct rte_mbuf **pkts, uint32_t n, uint32_t *res,
		uint64_t *pkts_mask, void **sess_info);


/**
 * Gate the incoming pkts based on PCC entry info.
 * @param sess_info
 *	list of per sdf bearer session struct pointers.
 *	pcc information.
 * @param  n
 *	number of pkts.
 * @param  pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 *
 * @return
 * Void
 */
void
pcc_gating(void **pcc_info, uint32_t n, uint64_t *pkts_mask);

/**
 * Get ADC filter entry.
 * @param rid
 *	ADC rule id.
 * @param n
 *	num. of rule ids.
 * @param pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param adc_info
 *	ADC information.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
adc_rule_info_get(uint32_t *rid, uint32_t n, uint64_t *pkts_mask, void **adc_info);

/**
 * Get Meter profile index from sdf per bearer session info.
 * @param sess_info
 *	pointer to struct dp_sdf_per_bearer_info.
 * @param mtr_id
 *	meter profile index to be returned
 * @param n
 *	number of pkts.
 */
void
get_sdf_mtr_id(void **sess_info, void **mtr_id, uint32_t n);

/**
 * Update CDR records per adc per ue.
 * @param adc_ue_info
 *	list of per adc ue structs pointer.
 * @param  pkts
 *	mbuf pkts.
 * @param  n
 *	number of pkts
 * @param  adc_pkts_mask
 *	ADC bit mask to process the pkts,
 *	Bit is set to 0 if adc gating is closed.
 * @param  pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param  flow
 *	direction of flow (UL_FLOW, DL_FLOW).
 *
 * @return
 * Void
 */
void
update_adc_cdr(void **adc_ue_info,
		struct rte_mbuf **pkts, uint32_t n,
		uint64_t *adc_pkts_mask, uint64_t *pkts_mask,
		uint32_t flow);
/**
 * Update CDR records of per sdf per bearer.
 * @param adc_ue_info
 *	list of per adc ue structs pointer.
 * @param sess_info
 *	list of per sdf bearer structs pointer.
 * @param  pkts
 *	mbuf pkts.
 * @param  n
 *	number of pkts.
 * @param  adc_pkts_mask
 *	ADC bit mask to process the pkts,
 *	Bit is set to 0 if adc gating is closed.
 * @param  pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param  flow
 *	direction of flow (UL_FLOW, DL_FLOW).
 *
 * @return
 * Void
 */
void
update_sdf_cdr(void **adc_ue_info, void **sdf_bear_info,
		struct rte_mbuf **pkts, uint32_t n,
		uint64_t *adc_pkts_mask, uint64_t *pkts_mask, uint32_t flow);

/**
 * Update CDR records of bearer.
 * @param sess_info
 *	list of per sdf bearer structs pointer.
 * @param  pkts
 *	mbuf pkts.
 * @param  n
 *	number of pkts.
 * @param  pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param  flow
 *	direction of flow (UL_FLOW, DL_FLOW).
 *
 * @return
 * Void
 */
void
update_bear_cdr(void **sdf_bear_info,
		struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint32_t flow);

/**
 * Update CDR records per rating group.
 * @param sess_info
 *	list of per sdf bearer structs pointer.
 * @param  rgrp
 *	list of rating group ids, whose CDRs to be updated.
 * @param  pkts
 *	mbuf pkts.
 * @param  n
 *	number of pkts.
 * @param  pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param  flow
 *	direction of flow (UL_FLOW, DL_FLOW).
 *
 * @return
 * Void
 */
void
update_rating_grp_cdr(void **sess_info, uint32_t **rgrp,
		struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint32_t flow);
/**
 * Get APN Meter profile index.
 * @param sess_info
 *	pointer to struct dp_sdf_per_bearer_info.
 * @param mtr_id
 *	meter profile index to be returned
 * @param n
 *	number of pkts.
 */
void
get_apn_mtr_id(void **sess_info, void **mtr_id, uint32_t n);

/**
 * Function to process the ADC lookup with key of 32 bits.
 * @param  pkts
 *	mbuf pkts.
 * @param n
 *	number of pkts.
 * @param rid
 *	rule ids
 */
void
adc_hash_lookup(struct rte_mbuf **pkts, uint32_t n, uint32_t *rid, uint8_t is_ul);

/**
 * Compare and update ADC rules in ADC ACL lookup results from hash lookup
 * If we have non-zero rule id in rc at nth location, replace nth value of rb
 * with that rule id.
 * @param rb
 *	list of rule ids.
 * @param rc
 *	list of rule ids.
 * @param n
 *	number of pkts.
 */
void
update_adc_rid_from_domain_lookup(uint32_t *rb, uint32_t *rc, uint32_t n);

/**
 * Get rating group from the adc and pcc info entries.
 * @param adc_ue_info
 *  list of pointers to adc_ue_info struct.
 * @param  pcc_info
 *	PCC rule info.
 * @param  rgrp
 *	rating group list.
 * @param  n
 *	number of pkts.
 *
 * @return
 * Void
 */
void
get_rating_grp(void **adc_ue_info, void **pcc_info,
		uint32_t **rgrp, uint32_t n);

/**
 * Initialization of PCC Table Callback functions.
 */
void app_pcc_tbl_init(void);

/**
 * Initialization of ADC Table Callback functions.
 */
void app_adc_tbl_init(void);

/**
 * Initialization of Meter Table Callback functions.
 */
void app_mtr_tbl_init(void);

/**
 * Initialization of filter table callback functions.
 */
void app_filter_tbl_init(void);

/**
 * Initialization of Session Table Callback functions.
 */
void
app_sess_tbl_init(void);

/********************* ADC Rule Table ****************/
/**
 * Create ADC Rule table.
 * @param dp_id
 *	table identifier.
 * @param max_elements
 *	max number of elements in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int dp_adc_table_create(struct dp_id dp_id, uint32_t max_elements);

/**
 * Destroy ADC Rule table.
 * @param dp_id
 *	table identifier.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int dp_adc_table_delete(struct dp_id dp_id);

/**
 * Add entry in ADC Rule table.
 * @param dp_id
 *	table identifier.
 * @param entry
 *	element to be added in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int dp_adc_entry_add(struct dp_id dp_id, struct adc_rules *entry);

/**
 * Delete entry in ADC Rule table.
 * @param dp_id
 *	table identifier.
 * @param entry
 *	element to be deleted in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int dp_adc_entry_delete(struct dp_id dp_id, struct adc_rules *entry);

/********************* PCC Table ****************/
/**
 * Create PCC table.
 * @param dp_id
 *	table identifier.
 * @param max_elements
 *	max number of elements in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int dp_pcc_table_create(struct dp_id dp_id, uint32_t max_elements);

/**
 * Destroy PCC table.
 * @param dp_id
 *	table identifier.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int dp_pcc_table_delete(struct dp_id dp_id);

/**
 * Add entry in PCC table.
 * @param dp_id
 *	table identifier.
 * @param entry
 *	element to be added in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_pcc_entry_add(struct dp_id dp_id, struct pcc_rules *entry);

/**
 * Delete entry in PCC table.
 * @param dp_id
 *	table identifier.
 * @param entry
 *	element to be deleted in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_pcc_entry_delete(struct dp_id dp_id, struct pcc_rules *entry);

/********************* Bearer Session ****************/
/**
 * Create Bearer Session table.
 * @param dp_id
 *	table identifier.
 * @param max_element
 *	max number of elements in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int dp_session_table_create(struct dp_id dp_id, uint32_t max_elements);

/**
 * Destroy Bearer Session table.
 * @param dp_id
 *	table identifier.
 * @param max_element
 *	max number of elements in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int dp_session_table_delete(struct dp_id dp_id);

/**
 * To create Bearer session information per user. The information
 * regarding uplink should be updated when passing session.
 * To update downlink related params please refer session_modify().
 * @param dp_id
 *	table identifier.
 * @param  session
 *	Session information
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_session_create(struct dp_id dp_id, struct session_info *session);

/**
 * To modify Bearer session information per user. The information
 * regarding uplink and downlink should be updated when passing session.
 * @param dp_id
 *	table identifier.
 * @param  session
 *	Session information
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_session_modify(struct dp_id dp_id, struct session_info *session);

/**
 * To Delete Bearer session information of user.
 * @param dp_id
 *	table identifier.
 * @param  session
 *	Session information
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_session_delete(struct dp_id dp_id, struct session_info *session);

/********************* Meter Table ****************/
/**
 * Create Meter profile table.
 * @param dp_id
 *	table identifier.
 * @param max_element
 *	max number of elements in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_meter_profile_table_create(struct dp_id dp_id, uint32_t max_elements);

/**
 * Delete Meter profile table.
 * @param dp_id
 *	table identifier.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_meter_profile_table_delete(struct dp_id dp_id);

/**
 * Add Meter profile entry.
 * @param dp_id
 *	table identifier.
 * @param  mtr_entry
 *	meter entry
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_meter_profile_entry_add(struct dp_id dp_id, struct mtr_entry *mtr_entry);

/**
 * Delete Meter profile entry.
 * @param dp_id
 *	table identifier.
 * @param  mtr_entry
 *	meter entry
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_meter_profile_entry_delete(struct dp_id dp_id, struct mtr_entry *mtr_entry);

/**
 * @brief Called by CP to add to uplink look up table.
 *
 * This function is thread safe due to message queue implementation.
 */
int
iface_add_uplink_data(struct ul_bm_key *key,
			struct dp_session_info *value);

/**
 * @brief Called by CP to add to downlink look up table.
 *
 * This function is thread safe due to message queue implementation.
 */
int
iface_add_downlink_data(struct dl_bm_key *key,
			struct dp_session_info *value);

/**
 * @brief Called by CP to remove from uplink look up table.
 *
 * This function is thread safe due to message queue implementation.
 */
int iface_del_uplink_data(struct ul_bm_key *key);

/**
 * @brief Called by CP to remove from downlink look up table.
 *
 * This function is thread safe due to message queue implementation.
 */
int iface_del_downlink_data(struct dl_bm_key *key);

/**
 * @brief Called by DP to lookup key-value pair in uplink look up table.
 *
 * This function is thread safe (Read Only).
 */
int
iface_lookup_uplink_data(struct ul_bm_key *key,
		void **value);

/**
 * @brief Called by DP to do bulk lookup of key-value pair in uplink
 * look up table.
 *
 * This function is thread safe (Read Only).
 */
int
iface_lookup_uplink_bulk_data(const void **key, uint32_t n,
		uint64_t *hit_mask, void **value);
/**
 * @brief Called by DP to lookup key-value pair in downlink look up table.
 *
 * This function is thread safe (Read Only).
 */
int
iface_lookup_downlink_data(struct dl_bm_key *key,
		void **value);
/**
 * @brief Called by DP to do bulk lookup of key-value pair in downlink
 * look up table.
 *
 * This function is thread safe (Read Only).
 */
int
iface_lookup_downlink_bulk_data(const void **key, uint32_t n,
		uint64_t *hit_mask, void **value);
/**
 * @brief Called by DP to lookup key-value pair in adc ue look up table.
 *
 * This function is thread safe (Read Only).
 */
int
iface_lookup_adc_ue_data(struct dl_bm_key *key,
		void **value);
/**
 * @brief Function to return address of uplink hash table bucket, for the
 * 64 bits key.
 *
 * This function is thread safe (Read Only).
 */
struct rte_hash_bucket *bucket_ul_addr(uint64_t key);

/**
 * @brief Function to return address of downlink hash table
 * bucket, for the 64 bits key.
 *
 * This function is thread safe (Read Only).
 */
struct rte_hash_bucket *bucket_dl_addr(uint64_t key);

/**
 * @brief Function to create hash table..
 *
 */
int
hash_create(const char *name, struct rte_hash **rte_hash,
		uint32_t entries, uint32_t key_len);

/**
 * @brief Called by DP to lookup key-value in ADC table.
 *
 * This function is thread safe (Read Only).
 */
int iface_lookup_adc_data(const uint32_t key32,
		void **value);
/**
 * @brief Called by DP to Bulk lookup key-value in ADC table.
 *
 * This function is thread safe (Read Only).
 */
int
iface_lookup_adc_bulk_data(const void **key, uint32_t n,
		uint64_t *hit_mask, void **value);
/**
 * @brief Called by DP to lookup key-value in PCC table.
 *
 * This function is thread safe (Read Only).
 */
int iface_lookup_pcc_data(const uint32_t key32,
		struct dp_pcc_rules **value);

/********************* ADC SpondDNS Table ****************/
/**
 * Add entry in ADC dns table.
 * This function is thread safe due to message queue implementation.
 * @param entry
 *	element to be added in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
adc_dns_entry_add(struct msg_adc *entry);

/**
 * Delete entry in ADC dns table.
 * This function is thread safe due to message queue implementation.
 * @param entry
 *	element to be added in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
adc_dns_entry_delete(struct msg_adc *entry);

/**
 * To map rating group value to index
 * @param rg_val
 *	rating group.
 * @param  rg_idx_map
 *	index map structure.
 *
 * @return
 *	- 0  on success
 *	- -1 on failure
 */
int
add_rg_idx(uint32_t rg_val, struct rating_group_index_map *rg_idx_map);

#endif /* _MAIN_H_ */

