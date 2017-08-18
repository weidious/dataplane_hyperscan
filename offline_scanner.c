#include<stdio.h>
#include<stdint.h>
#include <string.h>
#include<rte_acl.h>
#include<rte_ip.h>

#include "offline_scanner.h"
#include "stat.h"
#define MAX_INLINE_RULES 10
#define MAX_RULE_CHAR_LEN 256
uint64_t go;
uint64_t drop;
static hs_database_t *database;
static hs_scratch_t *scratch;
static hs_compile_error_t *compile_err;

static char *rules[MAX_INLINE_RULES];
static unsigned flags[MAX_INLINE_RULES];
static int  rule_ids[MAX_INLINE_RULES];
static unsigned free_idx;

struct cxt{
	int matching_id;
	unsigned long long off;
};

static struct cxt cxt;

int db_init(int realRule)
{
	hs_error_t err;

	int j = 0;
	for(int j = 0; j < realRule; j++)
	{
		flags[j] = HS_FLAG_SINGLEMATCH;;
		rule_ids[j] = j;
	}
	
	free_idx = 1;
	err = hs_compile_multi((const char *const *)rules, flags, rule_ids, free_idx, 
				HS_MODE_BLOCK, NULL, &database, &compile_err);
	if (err != HS_SUCCESS)
	{
		fprintf(stderr, "ERROR: unable to compile pattern : %s\n", compile_err->message);
		hs_free_compile_error(compile_err);
		return (-1);
	}
	
	err = hs_alloc_scratch(database, &scratch);

	if(err != HS_SUCCESS) {
		fprintf(stderr, "ERROR: %d unable to allocate scratch spacce. Exiting. \n", err);
		hs_free_database(database);
		return(-1);
	}

}

int read_rules()
{
	const char *cfg_file = "pattern.txt";
	FILE *file = fopen(cfg_file, "r");
	if(!file){
		printf("File load failed");
		return -1;
	}
	
	char line[MAX_RULE_CHAR_LEN];
	size_t len = MAX_RULE_CHAR_LEN;

	int i = 0;
	while (i < MAX_INLINE_RULES && (fgets(line, len, file) != NULL))
	{
		rules[i] = strdup(line);
		i++;
	}
	fclose(file);
	
	return i;	
		
}

static int event_handler(unsigned int id, __rte_unused unsigned long long from, unsigned long long to, 
			__rte_unused unsigned int flags, void *cxt)
{
	struct cxt *match_cxt = cxt;
	match_cxt->matching_id = id;
	match_cxt->off = to;
	//printf("Match off: %llu ~ %llu\n",from,to);
	++drop;
	return 0;
}


void offline_scan(const char *resp, unsigned len)
{
	//printf("OffLine\n");
	
	int init_error = 0;
	
	init_error = read_rules();

	int _error = 0;
	_error = db_init(init_error);
	
	if (_error != 0){
		printf("Error with offline initializations");
	}

	cxt.matching_id = -1;

	if (hs_scan(database, resp, len, 0, scratch, event_handler, &cxt) != HS_SUCCESS){
		fprintf(stderr, "ERROR: Unable to scan input buffer. Exiting. \n");
		exit(-1);
	}
	if(cxt.matching_id==-1)
                ++go;
	//Idisplay_dns_stats();
}
