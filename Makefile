#   BSD LICENSE
#
#   Copyright(c) 2016-2017 Intel Corporation. All rights reserved.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

MAKEFLAGS += -j

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk
include $(NG_CORE)/config/ng-core_cfg.mk

#DIRS-y += pipeline
# binary name
APP = ngic_dataplane
# all source are stored in SRCS-y
SRCS-y := main.c\
	pkt_handler.c\
	cdr.c\
	config.c\
	init.c\
	dataplane.c\
	gtpu.c\
	offline_scanner.c\
	ether.c\
	ipv4.c\
	udp.c\
	acl.c\
	meter.c\
	adc_table.c\
	pcc_table.c\
	sess_table.c\
	commands.c\
	stats.c\
	pipeline/epc_load_balance.o\
	pipeline/epc_packet_framework.o\
	pipeline/epc_tx.o\
	pipeline/epc_rx.o\
	pipeline/epc_worker.o\
	pipeline/epc_arp_icmp.o\
	pipeline/epc_spns_dns.o\
	$(SRCDIR)/../interface/interface.o\
	$(SRCDIR)/../cp_dp_api/vepc_cp_dp_api.o\
	$(SRCDIR)/../test/simu_cp/nsb/nsb_test_util.o\
	$(SRCDIR)/../test/simu_cp/simu_cp.o\
	$(SRCDIR)/../interface/ipc/dp_ipc_api.o\
	$(SRCDIR)/../interface/udp/vepc_udp.o\

CFLAGS += -I$(SRCDIR)/
CFLAGS += -I$(SRCDIR)/../interface
CFLAGS += -I$(SRCDIR)/../interface/ipc
CFLAGS += -I$(SRCDIR)/../interface/udp
CFLAGS += -I$(SRCDIR)/../interface/sdn
CFLAGS += -I$(SRCDIR)/../interface/zmq
CFLAGS += -I$(SRCDIR)/../cp_dp_api
CFLAGS += -I$(SRCDIR)/../test/simu_cp
CFLAGS += -I$(SRCDIR)/../test/simu_cp/nsb
CFLAGS += -I$(SRCDIR)/pipeline
CFLAGS += -I$(SRCDIR)/../lib/libsponsdn
CFLAGS += -I$(HYPERSCANDIR)/src

CFLAGS += -Wno-psabi # suppress "The ABI for passing parameters with 64-byte alignment has changed in GCC 4.6"


CFLAGS += -DLDB_DP	# should be included for dataplane.
#For ZMQ SB interface enable ZMQSUB_BUILD OR ZMQCLNT_BUILD not both
ifneq (,$(findstring ZMQSUB_BUILD, $(CFLAGS)))
	SRCS-y += $(SRCDIR)/../interface/zmq/zmqsub.o
else ifneq (,$(findstring ZMQCLNT_BUILD, $(CFLAGS)))
	SRCS-y += $(SRCDIR)/../interface/zmq/zmqclient.o
endif
CFLAGS += -g -O3
#CFLAGS += -g -O0

# Un-comment below line to read fake cp config.
#CFLAGS += -DSIMU_CP

# ASR- Un-comment below line to enable PCC, ADC, CDR, FILTERING, METERING pipeline stages.
#CFLAGS += -DINCLUDE_PIPELINE_STAGE

# Un-comment below line to enable PCC, ADC, CDR, FILTERING, METERING pipeline stages.
#CFLAGS += -DINCLUDE_ADC_STAGE

# Un-comment below line to enable PCC, ADC, CDR, FILTERING, METERING pipeline stages.
#CFLAGS += -DINCLUDE_MTR_STAGE

# Un-comment below line to enable NIC and pipeline stats.
CFLAGS += -DSTATS

# Un-comment below line to get stats from command line (for test harness)
#CFLAGS += -DCMDLINE_STATS#more to run

# Un-comment below line to clear STATS after reading.
CFLAGS += -DSTATS_CLR

# Un-comment below line to enable pipeline out stats, STATS flag should be enabled.
#CFLAGS += -DOSTATS

# Un-comment below line to enable DNS stats.
CFLAGS += -DDNS_STATS

# Un-comment below line to enable core RX and core TX. All
# processing stages will be skipped.
#CFLAGS += -DRX_TX

# Un-comment below line to skip RX Meta access
#CFLAGS += -DSKIP_RX_META

# Un-comment below line to enable core RX, core LB and core TX. All
# processing stages will be skipped.
#CFLAGS += -DRX_LB_TX

# Un-comment below line to enable SDF Metering
#CFLAGS += -DSDF_MTR

# Un-comment below line to enable APN Metering
#CFLAGS += -DAPN_MTR

# Un-comment below line to enable ADC upfront.
CFLAGS += -DADC_UPFRONT

# Un-comment below line to enable hyperscan DPI.
CFLAGS += -DHYPERSCAN_DPI

# Un-comment below line to enable Rating group CDRs.
#CFLAGS += -DRATING_GRP_CDR

# Un-comment below line to skip LB rte_hash_crc_4byte
# and enable LB based on UE ip last byte.
#CFLAGS += -DSKIP_LB_HASH_CRC

# set SGI port action handler equal to S1U action handler.
#CFLAGS += -DSKIP_LB_GTPU_AH

# Un-comment below line to read acl rules from file.
#CFLAGS += -DACL_READ_CFG

# Un-comment below line if you have 16 x 1GB hugepages.
#CFLAGS += -DHUGE_PAGE_16GB

CFLAGS += -Werror
CFLAGS_config.o := -D_GNU_SOURCE

# workaround for a gcc bug with noreturn attribute
#  http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_dataplane.o += -Wno-return-type
endif

LDFLAGS += -L/usr/local/lib -lzmq
LDFLAGS += -L$(RTE_SRCDIR)/../lib/libsponsdn/lib/libsponsdn/x86_64-native-linuxapp-gcc/ -lsponsdn

LDFLAGS += -L$(HYPERSCANDIR)/build/lib

LDFLAGS += -lexpressionutil -lhs -lhs_runtime -lstdc++ -lm

LDFLAGS += -lrte_pmd_af_packet

include $(RTE_SDK)/mk/rte.extapp.mk
