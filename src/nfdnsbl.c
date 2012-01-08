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
#include <netdb.h>

#ifdef ENABLE_SYSLOG
#include <syslog.h>
#endif

extern int h_errno;

option_t option;

void exit_callback(void)
{
	destroy_option(&option);

#ifdef ENABLE_SYSLOG
	closelog();
#endif
}

void log_debug(int level, const char* fmt, ...)
{
	int priority;
	if(option.debug < level)
		return;
	va_list args;
	va_start(args,fmt);
#ifndef ENABLE_SYSLOG
	if(!option.daemonize) //stdout is closed
	{
        	vfprintf(stdout,fmt,args);
		fprintf(stdout,"\n");
	}
#else
	switch(level){
		case 0:
			priority = LOG_INFO;
			break;
		case 1:
			priority = LOG_ERR;
			break;
		default:
			priority = LOG_DEBUG;
	}
	vsyslog(priority,fmt,args);
#endif
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
		log_debug(2,"Packet rejected!");
		return nfq_set_verdict2( qh, id, option.reject_verdict, option.reject_mark,0,NULL);
	}
}

void reverse_ip4(char* ip_addr,char* dest)
{
	char* b[4];
	char* saveptr;
	int i;

	for(i = 0; i < 4; i++)
	{
		b[i] = strtok_r(ip_addr,".",&saveptr);
		ip_addr = NULL;
	}
	dest[0] = '\0';
	for(i = 3; i >= 0; i--)
	{
		strcat(dest,b[i]);
		strcat(dest,".");
	}
}

char make_decision(char* ip_addr)
{
	char* dns;
	int addr_len, dnsbl_len;
	struct hostent *host;

	if(!ip_addr) //Something is wrong, paranoia is good
		return 0;
	
	addr_len = strlen(ip_addr);
	dnsbl_len = strlen(option.dnsbl);
	
	if(strchr(ip_addr,'.')) //IPv4
	{
		dns = (char*)malloc(addr_len+dnsbl_len+2);
		reverse_ip4(ip_addr,dns);
		dns[addr_len] = '.';
		memcpy(dns+addr_len+1,option.dnsbl,dnsbl_len);
		dns[addr_len+dnsbl_len+1] = '\0';
		log_debug(2,"Resolving %s",dns);
		host = gethostbyname(dns);

		if (host == NULL) {
			if (h_errno != HOST_NOT_FOUND) {
				log_debug(1, "Error looking up host %s",
					dns);
				return 0;
			}
			log_debug(2, "Host %s is clean",dns);
			return 1;
		}
		else
		{
			log_debug(2, "Host %s is in blacklist",dns);
			return 0;
		}
	}
	else	// IPv6
	{	
		return 1;
	}
	
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

void daemonize(void)
{
	pid_t pid, sid;

	/* Fork off the parent process */
	pid = fork();
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	/* If we got a good PID, then
	 * we can exit the parent process. 
	 */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/* Change the file mode mask */
	umask(0);

#ifdef ENABLE_SYSLOG
	openlog(PACKAGE_NAME,LOG_PID,LOG_DAEMON);
#endif
	
	/* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0) {
		log_debug(1,"Unable to start, setsid failed!");
		exit(EXIT_FAILURE);
	}

	/* Change the current working directory */
	if ((chdir("/")) < 0) {
		log_debug(1,"Unable to start, chdir failed!");
		exit(EXIT_FAILURE);
	}

	/* Close out the standard file descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

}

int main(void)
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

	if(option.daemonize)
		daemonize();

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

