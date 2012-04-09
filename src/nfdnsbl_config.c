#include "nfdnsbl_config.h"
#include <libconfig.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/netfilter.h>

#define DEFAULT_HOST "localhost"

int read_config(option_t* options,const char* config_file)
{
	config_t config;

	// Init config struct
	config_init(&config);

	if(config_read_file(&config, config_file) == CONFIG_FALSE)
	{
		if (config_error_type(&config) == CONFIG_ERR_PARSE) {
			fprintf (stderr, "Error parsing config file %s, line %d: %s\n",
				config_error_file(&config),
				config_error_line(&config),
				config_error_text(&config));
		}
		if (config_error_type(&config) == CONFIG_ERR_FILE_IO) {
			fprintf (stderr, "Error reading config file: %s\n",
			config_error_text(&config));
		}
		exit(EXIT_FAILURE);
	}
	config_lookup_int(&config, "options.accept_verdict", &(options->accept_verdict));
	config_lookup_int(&config, "options.reject_verdict", &(options->reject_verdict));
	config_lookup_int(&config, "options.accept_mark", &(options->accept_mark));
	config_lookup_int(&config, "options.reject_mark", &(options->reject_mark));
	config_lookup_int(&config, "options.queue", &(options->queue));
	config_lookup_int(&config, "options.debug", &(options->debug));
	config_lookup_int(&config, "options.daemonize", &(options->daemonize));
	config_lookup_int(&config, "options.paranoid", &(options->paranoid));
	config_lookup_int(&config, "options.gid", &(options->gid));
	config_lookup_int(&config, "options.uid", &(options->uid));
	config_lookup_string(&config, "options.dnsbl", (const char**)&(options->dnsbl));

	config_destroy(&config);

	return 0;
}

void init_option(option_t* option)
{
	option->dnsbl = (char*)malloc(sizeof(DEFAULT_HOST));
	if(option->dnsbl == NULL)
	{
		fprintf(stderr,"Malloc returned NULL.");
		exit(EXIT_FAILURE);
	}
	strcpy(option->dnsbl,DEFAULT_HOST);

	option->accept_verdict = NF_ACCEPT;
	option->reject_verdict = NF_DROP;
	option->accept_mark = 0;
	option->reject_mark = 0;
	option->queue = 0;
	option->debug = 0;
	option->daemonize = 0;
	option->paranoid = 0;
	option->gid = 0;
	option->uid= 0;
}

void destroy_option(option_t* option)
{
	free(option->dnsbl);
}

extern log_debug(int,char*,...);

void print_option(option_t* option)
{
	log_debug(2,"Options:\n\
		accept_verdict: %u\n\
		reject_verdict: %u\n\
		accept_mark: %u\n\
		reject_mark: %u\n\
		queue: %u\n\
		dnsbl: %s\n\
		debug: %d\n\
		daemonize: %d\n\
		gid: %d\n\
		uid: %d\n\
		paranoid: %d\n",
		option->accept_verdict,
		option->reject_verdict,
		option->accept_mark,
		option->reject_mark,
		option->queue,
		option->dnsbl,
		option->debug,
		option->daemonize,
		option->gid,
		option->uid,
		option->paranoid);
}
