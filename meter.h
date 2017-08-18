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

#ifndef _METER_H_
#define _METER_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of dataplane meter config and handlers.
 */
#include <rte_mbuf.h>
#include <rte_meter.h>

/**
 * config meter entry.
 *
 * @param msg_id
 *	message id.
 * @param msg_payload
 *	pointer to msg_payload
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
mtr_cfg_entry(int msg_id, void *msg_payload);

/**
 * Process APN metering based on meter index.
 *
 * @param mtr_id
 *	meter id
 * @param mtr_drp
 *	count of pkts dropped due to meter action.
 * @param pkt
 *	mbuf pointer
 * @param n
 *	num. of pkts.
 * @param pkts_mask
 *	bit mask to process the pkts,
 *	reset bit to free the pkt.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
mtr_process_pkt(void **mtr_id, uint64_t **mtr_drp, struct rte_mbuf **pkt,
			uint32_t n, uint64_t *pkts_mask);

#endif				/* _METER_H_ */
