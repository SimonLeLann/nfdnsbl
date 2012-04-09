#ifndef _NFDNSBL_CONFIG_H_
#define _NFDNSBL_CONFIG_H_

typedef struct option_t
{
	int accept_verdict; // Verdict to use when ok
	int reject_verdict; // Verdict to use when not ok
	int accept_mark; //mark to set when ok
	int reject_mark; //mark to set when not ok
	int queue; //queue to listen to
	char* dnsbl; // Address of the dnsbl
	int debug; // Debug level. the lower, the quieter.
	int daemonize; // Shall we daemonize?
	int paranoid; // Policy when we get errors
	int gid;
	int uid;
} option_t;


int read_config(option_t* ,const char*);

void init_option(option_t*);

void destroy_option(option_t*);

void print_option(option_t*);

#endif //_NFDNSBL_CONFIG_H_
