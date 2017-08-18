/*
 * Copyright statement
 */ 

#include <stdlib.h>
#include <stdint.h>
#include <hs.h>

#include "main.h"
int db_init(int realRule);

int read_rules();

static int event_handler(unsigned int id, __rte_unused unsigned long long from, unsigned long long to,
			 __rte_unused unsigned int flags, void *cxt);
/*
 * Scan a packet for a patterned defined in a cfg file
 * @param resp
 * Packets to scan, stored in rte_mbug
 * @param len
 * Packet length
 * @param pkt_mask
 * The mask of the packets, to be altered if packet should be dropped
 */


void offline_scan(const char *resp, unsigned len);


