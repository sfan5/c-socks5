#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#include <ares.h>

#include "dns.h"
#include "main.h"
#include "config.h"

struct dns_result {
	struct hostent *ent;
	int request_id;
};

static ares_channel channel;
static int wakeup_pipe[2], result_pipe[2];

static inline void ares_perror(const char *s, int r);
static void process_single(void *arg, int status, int timeouts, struct hostent *host);
static void *mainloop(void*);

int dns_init(void)
{
	int r = ares_library_init(ARES_LIB_INIT_ALL);
	if (r != ARES_SUCCESS) {
		ares_perror("ares_library_init", r);
		return -1;
	}

	struct ares_options options = {0};
	int optmask = ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS;
	options.flags = ARES_FLAG_STAYOPEN;
	options.timeout = config.connect_timeout / 2;
	if (config.dns_server) {
		// disable search domain + hosts querying if any dns servers set
		options.flags |= ARES_FLAG_NOSEARCH;
		options.lookups = "b";
		optmask |= ARES_OPT_LOOKUPS;
	}
	r = ares_init_options(&channel, &options, optmask);
	if (r != ARES_SUCCESS) {
		ares_perror("ares_init_options", r);
		return -1;
	}

	if (config.dns_server) {
		// build and set list of DNS servers
		struct ares_addr_node *head, *c;
		c = head = calloc(1, sizeof(struct ares_addr_node));
		for (struct config_addr_list *cc = config.dns_server; cc; cc = cc->next) {
			if (c != head) {
				c->next = calloc(1, sizeof(struct ares_addr_node));
				c = c->next;
			}
			c->family = cc->addr.ss_family;
			if (c->family == AF_INET6)
				memcpy(&c->addr.addr6, &((struct sockaddr_in6*) &cc->addr)->sin6_addr, 16);
			else
				c->addr.addr4 = ((struct sockaddr_in*) &cc->addr)->sin_addr;
		}

		r = ares_set_servers(channel, head);
		if (r != ARES_SUCCESS) {
			ares_perror("ares_set_servers", r);
			ares_destroy(channel);
			return -1;
		}

		for (c = head; c; ) {
			struct ares_addr_node *next = c->next;
			free(c);
			c = next;
		}
		free_addr_list(config.dns_server);
		config.dns_server = NULL;
	}

	if (pipe(wakeup_pipe) == -1)
		return -1;
	if (pipe(result_pipe) == -1)
		return -1;

	// so we can check for new data in a while loop (see dns_read_response)
	int flags = fcntl(result_pipe[0], F_GETFL, 0);
	if (flags == -1 || fcntl(result_pipe[0], F_SETFL, flags | O_NONBLOCK) == -1) {
		perror("fcntl");
		return -1;
	}

	pthread_t t;
	if (pthread_create(&t, NULL, mainloop, NULL) == -1)
		return -1;
	pthread_detach(t);
	return 0;
}

int dns_get_readable_fd(void)
{
	return result_pipe[0];
}

int dns_request(int request_id, const char *name, bool aaaa)
{
	/*
	 * Note that c-ares may call process_single on the same thread as this
	 * function if it can instantly resolve a name.
	 * This isn't an issue since small fixed-size pipe IO is atomic:
	 * https://unix.stackexchange.com/questions/346755/are-pipe-reads-not-greater-than-pipe-buf-atomic
	 */

	ares_gethostbyname(channel, name, aaaa ? AF_INET6 : AF_INET,
		process_single, (void*)(intptr_t)request_id);

	// make sure the dns thread isn't sleeping
	write(wakeup_pipe[1], ".", 1);

	return 0;
}

int dns_read_response(int *request_id, struct hostent **result)
{
	struct dns_result res;
	int r = read(result_pipe[0], &res, sizeof(res));
	if (r == -1 && errno == EWOULDBLOCK)
		return 0;
	else if (r != sizeof(res))
		abort();

	*request_id = res.request_id;
	*result = res.ent;
	return 1;
}

void dns_free_hostent(struct hostent *ent)
{
	free(ent->h_addr_list);
	free(ent);
}

static inline void ares_perror(const char *s, int r)
{
	fprintf(stderr, "%s: %s\n", s, ares_strerror(r));
}

static void process_single(void *arg, int status, int timeouts, struct hostent *host)
{
	struct dns_result res;
	res.request_id = (int)(intptr_t)arg;

	if (status != ARES_SUCCESS) {
		res.ent = NULL;
		goto reply;
	}

	// create a copy of the hostent structure
	res.ent = calloc(1, sizeof(struct hostent));
	if (!res.ent)
		goto reply;

	res.ent->h_name = NULL;
	res.ent->h_aliases = NULL;
	res.ent->h_addrtype = host->h_addrtype;
	res.ent->h_length = host->h_length;
	int addrs = 0;
	for (char **p = host->h_addr_list; *p; p++)
		addrs++;
	// a bit more compact:
	char *buf = calloc(1, (addrs+1) * sizeof(char*) + addrs * host->h_length);
	res.ent->h_addr_list = (char**) buf;
	buf += (addrs+1) * sizeof(char*);
	for (int i = 0; i < addrs; i++) {
		res.ent->h_addr_list[i] = buf;
		memcpy(buf, host->h_addr_list[i], host->h_length);
		buf += host->h_length;
	}

reply:
	if (write(result_pipe[1], &res, sizeof(res)) != sizeof(res))
		abort();
}

static void *mainloop(void *unused)
{
	fd_set read_fds, write_fds;
	struct timeval tv, *tvp;
	int nfds, r;

	while (1) {
		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		tvp = NULL;

		nfds = ares_fds(channel, &read_fds, &write_fds);
		if (nfds != 0)
			tvp = ares_timeout(channel, NULL, &tv);
		FD_SET(wakeup_pipe[0], &read_fds);
		if (wakeup_pipe[0]+1 > nfds)
			nfds = wakeup_pipe[0]+1;

		r = select(nfds, &read_fds, &write_fds, NULL, tvp);
		if (r == -1) {
			perror("select");
			continue;
		}

		if (FD_ISSET(wakeup_pipe[0], &read_fds)) {
			char unused[50];
			read(wakeup_pipe[0], unused, sizeof(unused));
		}
		ares_process(channel, &read_fds, &write_fds);
	}

	return NULL;
}
