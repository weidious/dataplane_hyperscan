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

#ifndef _UTIL_H_
#define _UTIL_H_

#define _GNU_SOURCE     /* Expose declaration of tdestroy() */
#include <search.h>
#include "vepc_cp_dp_api.h"
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of dataplane utilities.
 */
/**
 * gtpu header size.
 */
#define GPDU_HDR_SIZE		8

/**
 * ipv4 header size.
 */
#define IPv4_HDR_SIZE		20

/**
 * udp header size.
 */
#define UDP_HDR_SIZE		8

/**
 * ethernet header size for untagged packet.
 */
#define ETH_HDR_SIZE		14

 /**
 * macro to define next protocol udp in
 * ipv4 header.
 */
#define IP_PROTO_UDP		17

/**
 * GTPU port
 */
#define UDP_PORT_GTPU		2152

/**
 * network order DNS src port for udp
 */
#define N_DNS_RES_SRC_PORT      0x3500

/**
 * ipv4 address format.
 */
#define IPV4_ADDR "%u.%u.%u.%u"
#define IPV4_ADDR_FORMAT(a)	(uint8_t)((a) & 0x000000ff), \
				(uint8_t)(((a) & 0x0000ff00) >> 8), \
				(uint8_t)(((a) & 0x00ff0000) >> 16), \
				(uint8_t)(((a) & 0xff000000) >> 24)
#define IPV4_ADDR_HOST_FORMAT(a)	(uint8_t)(((a) & 0xff000000) >> 24), \
				(uint8_t)(((a) & 0x00ff0000) >> 16), \
				(uint8_t)(((a) & 0x0000ff00) >> 8), \
				(uint8_t)((a) & 0x000000ff)

struct table {
	char name[MAX_LEN];
	void *root;
	uint16_t num_entries;
	uint16_t max_entries;
	uint8_t active;
	int (*compare)(const void *r1p, const void *r2p);
	void (*print_entry)(const void *nodep, const VISIT which, const int depth);
};

#endif /*_UTIL_H_ */
