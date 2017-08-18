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
 *! \file udp.h
 *  \brief UDP header file.
 *	This file contail the Macros, structures and prototype of UDP.
 */

#ifndef _UDP_H_
#define _UDP_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of dataplane udp header constructor.
 */
#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_udp.h>
#include "util.h"

/**
 * Function to return pointer to udp headers.
 *
 * @param m
 *	mbuf pointer
 *
 * @return
 *	pointer to udp headers
 */
static inline struct udp_hdr *get_mtoudp(struct rte_mbuf *m)
{
	return (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) +
				    ETH_HDR_SIZE + IPv4_HDR_SIZE);
}

/**
 * Function to construct udp header.
 *
 * @param m
 *	mbuf pointer
 * @param len
 *	len of header
 * @param sport
 *	src port
 * @param dport
 *	dst port
 *
 * @return
 *	None
 */
void
construct_udp_hdr(struct rte_mbuf *m, uint16_t len,
		  uint16_t sport, uint16_t dport);

#endif				/* _UDP_H_ */
