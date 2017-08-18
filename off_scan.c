#include<stdio.h>
#include<stdint.h>
#include <string.h>
#include<rte_acl.h>
#include<rte_ip.h>

#include "off_scan.h"
#define MAX_INLINE_RULES 10


static char *rules[MAX_INLINE_RULES];
static unsigned all_flags[MAX_INLINE_RULES];
static int  all_rule_ids[MAX_INLINE_RULES];
static unsigned free_idx;
static hs_database_t *database2;
static hs_scratch_t *scratch2;
static hs_compile_error_t *compile_err2;

struct ctx {
        unsigned matching_id;
        unsigned long long off;
};

static struct ctx ctx;

static int event(unsigned int id, __rte_unused unsigned long long from, unsigned long long to,
                      __rte_unused unsigned int flags, void *cxt)
{
         printf("Match for pattern \"%s\" at offset %llu\n", rules[id], to);

                struct ctx *match_ctx = cxt;
                 match_ctx->matching_id = id;
                 match_ctx->off = to;

                return 0;
}



int offline_scan(const char *resp, unsigned len){

                printf("In offline scan\n");
                 const char *cfg_file = "pattern.txt";
                 FILE *fd = fopen(cfg_file, "r");
                 if(!fd)
                    printf("File load failed");

        char line[1024];
         int i = 0;
        while (i <MAX_INLINE_RULES  || (fgets(line, 1024, fd) != NULL))
        {
                rules[i] = strdup(line);
               i++;
        }
                    hs_error_t err;
        for(int j = 0; j < i; j++)
        {
                all_flags[j] = HS_FLAG_SINGLEMATCH;
                all_rule_ids[j] = j;
        }
        free_idx = i;
         err = hs_compile_multi((const char *const *)rules, all_flags, all_rule_ids, free_idx,
                                HS_MODE_BLOCK, NULL, &database2, &compile_err2);
        if (err != HS_SUCCESS)
        {
                fprintf(stderr, "ERROR: unable to compile pattern : %s\n", compile_err2->message);
                hs_free_compile_error(compile_err2);
                return (-1);
        }

        err = hs_alloc_scratch(database2, &scratch2);

        if(err != HS_SUCCESS) {
                fprintf(stderr, "ERROR: %d unable to allocate scratch spacce. Exiting. \n", err);
                hs_free_database(database2);
                return(-1);
        }
        int *cxt= 0;
        if (hs_scan(database2, resp, len, 0, scratch2, event, &cxt) != HS_SUCCESS){
	  fprintf(stderr, "ERROR: Unable to scan input buffer. Exiting. \n");
                exit(-1);
        }


        return 0 ;
}

