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

#ifndef _STATS_H_
#define _STATS_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of dataplane nic and pipeline stats.
 */
#include <rte_pipeline.h>
/**
 * Function to display IN stats of a pipeline.
 *
 * @param p
 *	rte pipeline.
 * @param port_id
 *	port id.
 *
 * @return
 *	None
 */
void display_pip_istats(struct rte_pipeline *p, char *name, uint8_t port_id);

/**
 * Function to display IN stats for all pipelines.
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void display_pip_ictrs(void);

/**
 * Function to display OUT stats of a pipeline.
 *
 * @param p
 *	rte pipeline.
 * @param name
 *	pipeline name
 * @param port_id
 *	port id.
 *
 * @return
 *	None
 */
void display_pip_ostats(struct rte_pipeline *p, char *name, uint8_t port_id);

/**
 * Function to display OUT stats for all pipelines.
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void display_pip_octrs(void);

/**
 * Function to display NIC stats.
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void display_nic_stats(void);

/**
 * Function to display action handler stats of each pipeline.
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void display_ah_ctrs(void);

/**
 * Function to display instrumentation data of workers.
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void display_instmnt_wrkr(void);

/**
 * Core to print the pipeline stats.
 *
 * @param
 *	Unused
 *
 * @return
 *	None
 */
void epc_stats_core(__rte_unused void *args);

#endif /*_STATS_H_ */
