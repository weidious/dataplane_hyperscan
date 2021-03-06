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

#ifndef _CDR_H
#define _CDR_H
/**
 * @file
 * This file contains function prototypes of User data
 * charging record.
 */
#include "main.h"

/**
 * Initialize Charging data record file.
 */
void cdr_init(void);

/**
 * Export PCC record to file
 * @param pcc_rule
 *	PCC rule.
 * @param cdr
 *	charge data record.
 * @param session
 *	bearer session info.
 *
 * @return
 * Void
 */
void export_session_pcc_record(struct dp_pcc_rules *pcc_rule,
					struct ipcan_dp_bearer_cdr *cdr,
					struct dp_session_info *session);

/**
 * Export ADC record to file
 * @param adc_rule
 *	ADC rule.
 * @param cdr
 *	charge data record.
 * @param session
 *	bearer session info.
 *
 * @return
 * Void
 */
void export_session_adc_record(struct adc_rules *adc_rule,
					struct ipcan_dp_bearer_cdr *cdr,
					struct dp_session_info *session);
#endif /* _CDR_H */
