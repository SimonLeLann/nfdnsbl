#include "nfdnsbl_config.h"
#include "config.h"
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

option_t option;

void exit_callback(void)
{
	destroy_option(&option);
}

void log_debug(int level, const char* fmt, ...)
{
	va_list args;
	va_start(args,fmt);
        vfprintf(stdout,fmt,args);
	fprintf(stdout,"\n");
	va_end(args);
}

const char* extract_ip(const char* payload,int size)
{
	unsigned char ip[16];
	int version;
	char* ret;

	if(size < 1)
	{
		log_debug(1,"Can't read IP version! size: %d",size);
		return NULL;
	}

	version = payload[0] & 0xF0;
	version >>= 4;

	if(size < ((version==4)?16:24))
	{
		log_debug(1,"Packet too short for IPv%d! size=%d",version,size);
		return NULL;
	}
	if(version == 4)
	{
		memcpy(ip,payload+12,4);
		ret = (char*)malloc(INET_ADDRSTRLEN);
		return inet_ntop(AF_INET,(struct in_addr*)ip,ret,INET_ADDRSTRLEN);
	}
	else if(version == 6)
	{
		memcpy(ip,payload+8,16);
		ret = (char*)malloc(INET6_ADDRSTRLEN);
		return inet_ntop(AF_INET6,(struct in6_addr*)ip,ret,INET6_ADDRSTRLEN);
	}
	else
		return NULL;
}

int set_verdict(struct nfq_q_handle * qh, unsigned int id, char verdict)
{
	if(verdict) // Packet is ok
	{
		log_debug(2,"Packet accepted!");
		return nfq_set_verdict2( qh, id, option.accept_verdict, option.accept_mark,0,NULL);
	}
	else
	{
		return nfq_set_verdict2( qh, id, option.reject_verdict, option.reject_mark,0,NULL);
		log_debug(2,"Packet rejected!");
	}
}

char make_decision(const char* ip_addr)
{
	if(!ip_addr) //Something is wrong, paranoia is good
		return 0;
	if(!strcmp(ip_addr,"127.0.0.1"))
		return 1;

	log_debug(2,"No decision taken, reject by default!");
	return 0;
}

static int packet_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,struct nfq_data *nfa, void *data) 
{
	int ret;
	struct nfqnl_msg_packet_hdr *ph;
	unsigned char *nfdata;
	char* ip_addr;
	unsigned int id;
	char verdict;

	if (ph = nfq_get_msg_packet_hdr(nfa)) {
		id = ntohl(ph->packet_id);
	}

	log_debug(2,"Entering packet_callback");

	if((ret = nfq_get_payload(nfa, &nfdata)) == -1)
		log_debug(1,"Error while retrieving payload.");

	if((ip_addr = extract_ip(nfdata,ret)) == NULL)
		log_debug(1,"Unable to decode ip address!");

	log_debug(2,"Received a packet from %s.",ip_addr);

	verdict = make_decision(ip_addr);

	free(ip_addr);

	return set_verdict(qh,id,verdict);

}

#define BUFSIZE 256

int main()
{
	struct nfq_handle *h;
	struct nfq_q_handle *handle;
	struct nfnl_handle *nh;
	int fd, rv;
	char buf[BUFSIZE];
	struct stat fbuf;


	init_option(&option);
	atexit(exit_callback);
	read_config(&option,CONFFILE);
	print_option(&option);

	if (stat("/proc/net/netfilter/nfnetlink_queue", &fbuf) == ENOENT) {
		fprintf(stderr, "Please make sure you have\ncompiled a kernel with the Netfilter QUEUE target built in, or loaded the appropriate module.\n");
		exit(EXIT_FAILURE);
	}

	log_debug(2,"Creating nfq handle...");
	if ((h = nfq_open()) == NULL) {
		log_debug(1, "Couldn't create nfq handle");
		exit(EXIT_FAILURE);
	}
	log_debug(2, "unbinding nfq handle...");
	if (nfq_unbind_pf(h, AF_INET6) < 0) {
		log_debug(1, "Couldn't unbind nf_queue handler for AF_INET");
		exit(EXIT_FAILURE);
	}
	log_debug(2, "binding nfq handle...");
	if (nfq_bind_pf(h, AF_INET6) < 0) {
		log_debug(1, "Couldn't bind ns_queue handler for AF_INET");
		exit(EXIT_FAILURE);
	}
	log_debug(2, "creating queue...");
	if ((handle = nfq_create_queue(h, option.queue, &packet_callback, NULL)) == NULL) {
		log_debug(1, "nfq_create_queue failed");
		exit(EXIT_FAILURE);
	}
	log_debug(2, "setting nfq mode");
	if(nfq_set_mode(handle,NFQNL_COPY_PACKET,24) == -1)
	{
		log_debug(1, "nfq_set_mode failed");
		exit(EXIT_FAILURE);
	}
	log_debug(0,"%s started successfully",PACKAGE_STRING);
	
	/* main packet processing loop.  This loop should never terminate
	 * unless a signal is received or some other unforeseen thing
	 * happens.
	 */
	while (1) {
		nh = nfq_nfnlh(h);
		fd = nfnl_fd(nh);
		log_debug(2, "Entering main loop.");
		log_debug(2, "waiting for a packet...");
		while ((rv = recv(fd, buf, sizeof(buf), 0)) > 0) {
			log_debug(2, "Handling a packet");
			nfq_handle_packet(h, buf, rv);
		}
		log_debug(2, "Packet got.");
	}
	// unbinding before exit
 	log_debug(2,"NFQUEUE: unbinding from queue '%hd'\n", option.queue);
	nfq_destroy_queue(handle);
	nfq_close(h);
	return EXIT_SUCCESS;
}

