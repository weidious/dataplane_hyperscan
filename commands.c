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

/*
 * Copyright (c) 2009, Olivier MATZ <zer0@droids-corp.org>
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the University of California, Berkeley nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of CLI processing.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <netinet/in.h>
#include <termios.h>
#ifndef __linux__
#ifdef __FreeBSD__
#include <sys/socket.h>
#else
#include <net/socket.h>
#endif
#endif

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_socket.h>
#include <cmdline.h>

#include <rte_string_fns.h>

#include "stats.h"

/**********************************************************/
struct cmd_show_result {
	cmdline_fixed_string_t show;
};

cmdline_parse_token_string_t cmd_show_show =
TOKEN_STRING_INITIALIZER(struct cmd_show_result, show, "show");

static void cmd_show_stats(void *parsed_result,
		struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	RTE_SET_USED(parsed_result);
	RTE_SET_USED(cl);
	RTE_SET_USED(data);
#ifdef STATS
	display_nic_stats();

	display_pip_ictrs();

#ifdef OSTATS
	display_pip_octrs();
#endif
#ifdef INSTMNT
	display_instmnt_wrkr();
#endif
#ifdef AH_STATS
	display_ah_ctrs();
#endif
#ifdef MTR_STATS
	display_mtr_stats();
#endif
#endif	/* STATS */

}

cmdline_parse_inst_t cmd_obj_show_stats = {
	.f = cmd_show_stats,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "Show stats",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_show_show,
		NULL,
	},
};

/**********************************************************/
struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

cmdline_parse_token_string_t cmd_quit_quit =
TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit");

static void cmd_quit_app(void *parsed_result,
		struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	RTE_SET_USED(parsed_result);
	RTE_SET_USED(cl);
	RTE_SET_USED(data);
	cmdline_stdin_exit(cl);
	rte_exit(0, NULL);
}

cmdline_parse_inst_t cmd_obj_quit_app = {
	.f = cmd_quit_app,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "Quit application",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_quit_quit,
		NULL,
	},
};

/**********************************************************/
struct cmd_help_result {
	cmdline_fixed_string_t help;
};

cmdline_parse_token_string_t cmd_help_help =
TOKEN_STRING_INITIALIZER(struct cmd_help_result, help, "help");

static void cmd_help(__attribute__((unused)) void *parsed_result,
		struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	RTE_SET_USED(parsed_result);
	RTE_SET_USED(data);
	cmdline_printf(cl,
			"Command supported:\n"
			"- show\n"
			"- quit\n"
			"- help\n\n");
}

cmdline_parse_inst_t cmd_obj_help = {
	.f = cmd_help,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "show help",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_help_help,
		NULL,
	},
};

/** CONTEXT (list of instruction) */

cmdline_parse_ctx_t main_ctx[] = {
	(cmdline_parse_inst_t *)&cmd_obj_show_stats,
	(cmdline_parse_inst_t *)&cmd_obj_quit_app,
	(cmdline_parse_inst_t *)&cmd_obj_help,
	NULL,
};
