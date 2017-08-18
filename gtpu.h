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
 *! \file gtpu.h
 *  \brief Gtpu header file.
 *	This file contail the Macros, structures and prototype of
 *	Gtpu protocol.
 */

#ifndef _GTPU_H_
#define _GTPU_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of GTPU header parsing and constructor.
 */
#include "util.h"

#define GTPU_VERSION		0x01
#define GTP_PROTOCOL_TYPE_GTP	0x01
#define GTP_GPDU		0xff

/**
 * Gpdu header structure .
 */

#pragma pack(1)
struct gtpu_hdr {
	uint8_t pdn:1;		/**< n-pdn number present ? */
	uint8_t seq:1;		/**< sequence no. */
	uint8_t ex:1;		/**< next extersion hdr present? */
	uint8_t spare:1;	/**< reserved */
	uint8_t pt:1;		/**< protocol type */
	uint8_t version:3;	/**< version */
	uint8_t msgtype;	/**< message type */
	uint16_t msglen;	/**< message length */
	uint32_t teid;		/**< tunnel endpoint id */
};
#pragma pack()

/**
 * Function to return pointer to gtpu headers.
 *
 * @param m
 *	mbuf pointer
 *
 * @return
 *	pointer to udp headers
 */
static inline struct gtpu_hdr *get_mtogtpu(struct rte_mbuf *m)
{
	return (struct gtpu_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) +
			ETH_HDR_SIZE + IPv4_HDR_SIZE + UDP_HDR_SIZE);
}

/**
 * Function for decapsulation of gtpu headers.
 *
 * @param m
 *	mbuf pointer
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int decap_gtpu_hdr(struct rte_mbuf *m);

/**
 * Function for encapsulation of gtpu headers.
 *
 * @param m
 *	mbuf pointer
 * @param teid
 *	tunnel endpoint id to be set in gtpu header.
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int encap_gtpu_hdr(struct rte_mbuf *m, uint32_t teid);

/**
 * Function to get inner dst ip of tunneled packet.
 *
 * @param m
 *	mbuf of the incoming packet.
 *
 * @return
 *	 inner dst ip
 */
uint32_t gtpu_inner_src_ip(struct rte_mbuf *m);

#endif	/* _GTPU_H_ */
