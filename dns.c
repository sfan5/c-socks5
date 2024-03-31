#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <poll.h>
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

#if ARES_VERSION < 0x010701
#error c-ares is too old
#endif

#ifndef ARES_OPT_EVENT_THREAD
#define ARES_OPT_EVENT_THREAD 0
#endif

struct dns_result {
	struct hostent *ent;
	int request_id;
};

static ares_channel channel;
static bool event_thread; // true = c-ares event thread, false = our own
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

	event_thread = false;
#if ARES_VERSION >= 0x011a00
	if (ares_threadsafety() == ARES_TRUE)
		event_thread = true;
#endif

#ifndef NDEBUG
	printf("running with c-ares %s (event_thread=%d)\n", ares_version(NULL), (int)event_thread);
#endif

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
	if (event_thread) {
		optmask |= ARES_OPT_EVENT_THREAD;
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

	if (event_thread) {
		wakeup_pipe[0] = wakeup_pipe[1] = -1;
	} else {
		if (pipe(wakeup_pipe) == -1)
			return -1;
	}
	if (pipe(result_pipe) == -1)
		return -1;

	// make sure dns_read_response can't block
	int flags = fcntl(result_pipe[0], F_GETFL, 0);
	if (flags == -1 || fcntl(result_pipe[0], F_SETFL, flags | O_NONBLOCK) == -1) {
		perror("fcntl");
		return -1;
	}

	if (!event_thread) {
		pthread_t t;
		if (pthread_create(&t, NULL, mainloop, NULL) == -1)
			return -1;
		pthread_detach(t);
	}
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

	if (!event_thread) {
		// make sure the dns thread isn't sleeping
		(void)write(wakeup_pipe[1], ".", 1);
	}

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
	struct pollfd fds[ARES_GETSOCK_MAXNUM + 1];
	struct timeval tv, *tvp;
	unsigned int nfds;

	if (event_thread)
		abort();

	while (1) {
		fds[0].fd = wakeup_pipe[0];
		fds[0].events = POLLIN;
		nfds = 1;
		tvp = NULL;

		{
			ares_socket_t afds[ARES_GETSOCK_MAXNUM];
			int mask = ares_getsock(channel, afds, ARES_GETSOCK_MAXNUM);
			for (int i = 0; i < ARES_GETSOCK_MAXNUM; i++) {
				fds[nfds].events = (ARES_GETSOCK_READABLE(mask, i) ? POLLIN : 0) |
					(ARES_GETSOCK_WRITABLE(mask, i) ? POLLOUT : 0);
				if (!fds[nfds].events)
					break;
				fds[nfds].fd = afds[i];
				nfds++;
			}
		}
		tvp = ares_timeout(channel, NULL, &tv);

		int r = poll(fds, nfds, tvp ?
			(tvp->tv_sec * 1000 + tvp->tv_usec / 1000) : -1);
		if (r == -1) {
			perror("poll");
			continue;
		}

		if (fds[0].revents) {
			char unused[50];
			(void)read(wakeup_pipe[0], unused, sizeof(unused));
		}
		bool any = false;
		for (int i = 1; i < nfds; i++) {
			bool read = !!(fds[i].revents & (POLLIN|POLLERR)),
				write = !!(fds[i].revents & POLLOUT);
			if (!read && !write)
				continue;
			ares_process_fd(channel, read ? fds[i].fd : ARES_SOCKET_BAD,
				write ? fds[i].fd : ARES_SOCKET_BAD);
			any = true;
		}
		if (!any)
			ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
	}

	return NULL;
}
