#define _POSIX_C_SOURCE 200112L
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>
#include <net/if.h>
#include <fcntl.h>
#ifdef __linux__
#include <linux/net.h>
#endif

#include "main.h"
#include "async.h"
#include "protocol.h"
#include "forwarder.h"
#include "dns.h"
#include "config.h"

// OS features
#if defined(__linux__)
#define USE_ACCEPT4
#define USE_SOCKET_NONBLOCK_FLAG
#endif

#define DEL_CLOSE 1
#define DEL_RECURSE 2

// https://tools.ietf.org/html/rfc8305
#define HAPPY_EYEBALLS_RESOLUTION_DELAY 50
#define HAPPY_EYEBALLS_CONN_ATTEMPT_DELAY 250

#define DNS_REQUEST_TABLE_CHUNK 32

// doesn't cost us anything to check so do it relatively often
#define IPV6_CONNECTABLE_CACHE_TIME 30

enum {
	// sockets with other purposes
	STATUS_LISTENER = 0,
	STATUS_DNS,
	// client socket
	// Note: timeouts are ever only set on this one
	STATUS_EXPECT_AUTH = 1000,
	STATUS_EXPECT_REQUEST,
	STATUS_WAIT_DNS,
	STATUS_WAIT_CONNECTION,
	// outgoing connection
	STATUS_OUTGOING_CONNECTION = 2000,
};

struct proto_state {
	union {
		struct { // for STATUS_EXPECT_AUTH .. STATUS_WAIT_CONNECTION
			struct proto_state *child_states[2];
			struct hostent *waiting_addr;
			int dns_request_ids[2];
			uint16_t remote_port;
		};
		struct proto_state *parent_state; // for STATUS_OUTGOING_CONNECTION
	};
	uint16_t status;
	int dns_overdue : 1;
};

struct request_table {
	struct proto_state *table[DNS_REQUEST_TABLE_CHUNK];
	struct request_table *next;
};

/**/

struct config_struct config;

static struct as_context *ctx;

static struct request_table request_table;

static void usage(void);
static int create_sockets(void);
static int create_outgoing_socket(int family);
static bool is_ipv6_connectable(void);
static inline int errno_to_socks_error(int error);
static inline void send_socks_error(int fd, int error);
static void sockaddr_from_hostent(struct sockaddr_storage *addr, const struct hostent *ent, uint16_t port);
static void delete_state(struct proto_state* user, int flags);
static int start_connection_attempt(struct proto_state *user, const struct sockaddr_storage *addr, int set_timeout);
static int request_table_allocate(struct proto_state *user);
static struct proto_state *request_table_retrieve(int id);
static void request_table_unset(int id);

static void socket_handler(int fd, int event, void *user);

int main(int argc, char *argv[])
{
	int r = read_args(argc, argv);
	if (r == -2)
		usage();
	if (r < 0)
		return 1;

	struct rlimit lim;
	if (getrlimit(RLIMIT_NOFILE, &lim) == 0) {
		const int warn_amount = 1024;
		if (lim.rlim_cur < warn_amount * 2) {
			fprintf(stderr, "Warning: current file resource limit allows less "
				"than %d connections, consider increasing it.\n", warn_amount);
		}
	}

	if (create_sockets() == -1)
		return 1;

	if (forwarder_init() == -1)
		return 1;

	if (dns_init() == -1)
		return 1;
	const struct proto_state new = {
		.status = STATUS_DNS,
	};
	if (!as_add_fd(ctx, dns_get_readable_fd(), AS_POLLIN, sizeof(new), &new))
		return 1;

	while (1) {
		as_poll(ctx, socket_handler);
	}

	return 0;
}

static void usage(void)
{
	printf("c-socks5 is a modern, high-performance SOCKS5 server\n");
	printf("Usage: c-socks5 [-c file] [-b addr:port] [--dns addr]\n");
	printf("\n");
	printf("Options:\n");
	static const struct { const char *l, *r; } opts[] = {
		{"-c file", "Load configuration from specified file"},
		{"-b addr:port", "Set address(es) to listen for incoming connections"},
		{"", "Same semantics as 'bind' in config file"},
		{"--dns addr", "Set DNS server(s)"},
		{"", "Same semantics as 'dns' in config file"},
		{NULL},
	};
	for(int i = 0; opts[i].l; i++)
		printf("  %-13s %s\n", opts[i].l, opts[i].r);
}

static int create_sockets(void)
{
	// async context
	ctx = as_create();
	if (!ctx)
		return -1;

	// listen socket(s)
	for (struct config_addr_list *c = config.bind_listener; c; c = c->next) {
		int listen_sock = socket(c->addr.ss_family, SOCK_STREAM, 0);
		if (listen_sock == -1) {
			perror("socket");
			return -1;
		}

		int opt = 1;
		setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
		if (c->addr.ss_family == AF_INET6) {
			opt = 1;
			setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(int));
		}

		if (bind(listen_sock, (struct sockaddr*) &c->addr, sizeof(c->addr)) == -1) {
			perror("bind");
			close(listen_sock);
			return -1;
		}
		if (listen(listen_sock, 128) == -1) {
			perror("listen");
			close(listen_sock);
			return -1;
		}

		int flags = fcntl(listen_sock, F_GETFL, 0);
		if (flags == -1 || fcntl(listen_sock, F_SETFL, flags | O_NONBLOCK) == -1) {
			perror("fcntl");
			close(listen_sock);
			return -1;
		}

		const struct proto_state new = {
			.status = STATUS_LISTENER,
		};
		if (!as_add_fd(ctx, listen_sock, AS_POLLIN, sizeof(new), &new)) {
			close(listen_sock);
			return -1;
		}
	}

	free_addr_list(config.bind_listener);
	config.bind_listener = NULL;

	return 0;
}

static int create_outgoing_socket(int family)
{
	int sock, r;
#ifdef USE_SOCKET_NONBLOCK_FLAG
	sock = socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0);
#else
	sock = socket(family, SOCK_STREAM, 0);
#endif
	if (sock == -1)
		return -1;

	if (config.bind_interface[0]) {
		const char *iface = config.bind_interface;
#ifdef __linux__
		r = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface) + 1);
#else
		errno = EOPNOTSUPP;
		r = -1;
#endif
		if (r == -1) {
			perror("setsockopt");
			close(sock);
			return -1;
		}
	} else {
		if (family == AF_INET && config.bind_address4.s_addr != INADDR_ANY) {
			struct sockaddr_in bind_addr = {
				.sin_family = AF_INET,
				.sin_addr = config.bind_address4,
				.sin_port = 0,
			};
			r = bind(sock, (struct sockaddr*) &bind_addr, sizeof(bind_addr));
		} else if (family == AF_INET6 && !IN6_IS_ADDR_UNSPECIFIED(&config.bind_address6)) {
			struct sockaddr_in6 bind_addr = {
				.sin6_family = AF_INET6,
				.sin6_addr = config.bind_address6,
				.sin6_port = 0,
			};
			r = bind(sock, (struct sockaddr*) &bind_addr, sizeof(bind_addr));
		} else {
			r = 0;
		}
		if (r == -1) {
			perror("bind");
			close(sock);
			return -1;
		}
	}

#ifndef USE_SOCKET_NONBLOCK_FLAG
	int flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
		perror("fcntl");
		close(sock);
		return -1;
	}
#endif

	return sock;
}

static bool is_ipv6_connectable(void)
{
	static bool cached;
	static time_t cached_time = 0;

	if (labs(time(NULL) - cached_time) <= IPV6_CONNECTABLE_CACHE_TIME)
		return cached;

	cached_time = time(NULL);
	cached = false;

	int sock;
	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock == -1)
		return false;

	if (config.bind_interface[0]) {
		const char *iface = config.bind_interface;
#ifdef __linux__
		setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface) + 1);
#endif
	} else if (!IN6_IS_ADDR_UNSPECIFIED(&config.bind_address6)) {
		struct sockaddr_in6 bind_addr = {
			.sin6_family = AF_INET6,
			.sin6_addr = config.bind_address6,
			.sin6_port = 0,
		};
		bind(sock, (struct sockaddr*) &bind_addr, sizeof(bind_addr));
	}

	struct sockaddr_in6 addr = {0};
	addr.sin6_family = AF_INET6;
	addr.sin6_addr.s6_addr[0] = 0x20;
	cached = connect(sock, (struct sockaddr*) &addr, sizeof(struct sockaddr_in6)) == 0;

	close(sock);
	return cached;
}

static inline int errno_to_socks_error(int error)
{
	switch (error) {
		case ECONNREFUSED:
			return SOCKS_REPLY_CONNREFUSED;
		case ENETUNREACH:
			return SOCKS_REPLY_NETUNREACH;
		case ETIMEDOUT:
			return SOCKS_REPLY_HOSTUNREACH;
		default:
			return SOCKS_REPLY_SERVERROR;
	}
}

static inline void send_socks_error(int fd, int error)
{
	char buf[20];
	buf[0] = SOCKS_VERSION;
	buf[1] = error;
	buf[2] = 0;
	buf[3] = SOCKS_ATYPE_IPV4;
	memset(buf+4, 0, 6); // dummy address
	send(fd, buf, 10, 0);
}

static void sockaddr_from_hostent(struct sockaddr_storage *addr, const struct hostent *ent, uint16_t port)
{
	addr->ss_family = ent->h_addrtype;
	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *a = (struct sockaddr_in6*) addr;
		memcpy(&a->sin6_addr, ent->h_addr, sizeof(struct in6_addr));
		a->sin6_port = port;
	} else {
		struct sockaddr_in *a = (struct sockaddr_in*) addr;
		memcpy(&a->sin_addr, ent->h_addr, sizeof(struct in_addr));
		a->sin_port = port;
	}
}

/**/

static void delete_state(struct proto_state* user, int flags)
{
	if (!user)
		return;
	//printf("delete_state(%d, %x)\n", as_get_fd(user), flags);
	assert(user->status >= STATUS_EXPECT_AUTH); // static states must never be deleted

	if (flags & DEL_RECURSE) {
		if (user->status == STATUS_OUTGOING_CONNECTION)
			return delete_state(user->parent_state, flags);
		delete_state(user->child_states[0], flags & ~DEL_RECURSE);
		delete_state(user->child_states[1], flags & ~DEL_RECURSE);
	}

	if (user->status != STATUS_OUTGOING_CONNECTION) {
		if (user->waiting_addr)
			dns_free_hostent(user->waiting_addr);
		if (user->dns_request_ids[0] != -1)
			request_table_unset(user->dns_request_ids[0]);
		if (user->dns_request_ids[1] != -1)
			request_table_unset(user->dns_request_ids[1]);
	}
#ifndef NDEBUG
	memset(user, 0xff, sizeof(struct proto_state)); // poison memory
#endif

	int fd = as_get_fd(user);
	as_del_fd(ctx, user);
	if (flags & DEL_CLOSE)
		close(fd);
}

static int start_connection_attempt(struct proto_state *user, const struct sockaddr_storage *addr, int set_timeout)
{
	int remote_sock, r;

	// create outgoing socket
	remote_sock = create_outgoing_socket(addr->ss_family);
	if (remote_sock == -1)
		return -SOCKS_REPLY_SERVERROR;

	// begin connection attempt
	r = connect(remote_sock, (struct sockaddr*) addr, sizeof(*addr));
	if (r == -1 && errno != EINPROGRESS) {
		close(remote_sock);
		return -errno_to_socks_error(errno);
	}

	// create a child state for it
	as_set_timeout(ctx, user, set_timeout);

	struct proto_state new = {0};
	new.status = STATUS_OUTGOING_CONNECTION;
	new.parent_state = user;
	void *new_state = as_add_fd(ctx, remote_sock, AS_POLLOUT, sizeof(new), &new);
	if (!new_state) {
		close(remote_sock);
		return -SOCKS_REPLY_SERVERROR;
	}
	int i = user->child_states[0] ? 1 : 0;
	assert(!user->child_states[i]);
	user->child_states[i] = new_state;

	user->status = STATUS_WAIT_CONNECTION;
	if (r == 0)
		// directly handle connection success
		socket_handler(remote_sock, AS_POLLOUT, new_state);
	return 0;
}

static int request_table_allocate(struct proto_state *user)
{
	struct request_table *cur = &request_table;
	int offset = 0;

	while (1) {
		for (int i = 0; i < DNS_REQUEST_TABLE_CHUNK; i++) {
			if (!cur->table[i]) {
				cur->table[i] = user;
				return offset + i;
			}
		}

		offset += DNS_REQUEST_TABLE_CHUNK;
		if (!cur->next) {
			cur->next = calloc(1, sizeof(struct request_table));
			if (!cur->next)
				abort();
		}
		cur = cur->next;
	}
}

static struct proto_state *request_table_retrieve(int id)
{
	struct request_table *cur = &request_table;
	assert(id >= 0);
	while (id >= DNS_REQUEST_TABLE_CHUNK) {
		id -= DNS_REQUEST_TABLE_CHUNK;
		if (!cur->next)
			return NULL;
		cur = cur->next;
	}
	return cur->table[id];
}

static void request_table_unset(int id)
{
	struct request_table *cur = &request_table;
	assert(id >= 0);
	while (id >= DNS_REQUEST_TABLE_CHUNK) {
		id -= DNS_REQUEST_TABLE_CHUNK;
		if (!cur->next)
			return assert(false);
		cur = cur->next;
	}
	assert(cur->table[id]);
	cur->table[id] = NULL;
}

/******/
/******/
/******/

static void handler_listener(int fd, int event)
{
	int conn_sock;
#ifdef USE_ACCEPT4
	conn_sock = accept4(fd, NULL, NULL, SOCK_NONBLOCK);
#else
	conn_sock = accept(fd, NULL, NULL);
#endif
	if (conn_sock == -1) {
		perror("accept");
		return;
	}

	int opt = 1;
	setsockopt(conn_sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(int));
#ifndef USE_ACCEPT4
	int flags = fcntl(conn_sock, F_GETFL, 0);
	if (flags == -1 || fcntl(conn_sock, F_SETFL, flags | O_NONBLOCK) == -1) {
		perror("fcntl");
		close(conn_sock);
		return;
	}
#endif

	struct proto_state new = {0};
	new.status = STATUS_EXPECT_AUTH;
	new.dns_request_ids[0] = -1;
	new.dns_request_ids[1] = -1;
	void *new_state = as_add_fd(ctx, conn_sock, AS_POLLIN, sizeof(new), &new);
	if (!new_state)
		close(conn_sock);
	else
		as_set_timeout(ctx, new_state, config.hello_timeout);
	return;
}

static void process_dns_response(struct proto_state *user, int request_id, struct hostent *ent)
{
	int fd = as_get_fd(user);
	const bool is_last = user->dns_request_ids[0] == -1 || user->dns_request_ids[1] == -1;
	{
		// unset our dns request id
		int i = request_id == user->dns_request_ids[0] ? 0 : 1;
		assert(i == 0 || request_id == user->dns_request_ids[1]);
		user->dns_request_ids[i] = -1;
	}

	if (ent && !ent->h_addr) { // so it's easier to work with
		dns_free_hostent(ent);
		ent = NULL;
	}

#ifndef NDEBUG
	if (ent) {
		char ipbuf[50];
		inet_ntop(ent->h_addrtype, ent->h_addr, ipbuf, sizeof(ipbuf));
		printf("dns %s\n", ipbuf);
	}
#endif

	int r;
	if (user->status == STATUS_WAIT_CONNECTION) {
		assert(is_last);
		if (!user->dns_overdue) {
			// queue IP up to be used when the connection delay expires
			assert(!user->waiting_addr);
			user->waiting_addr = ent;
			return;
		}
	} else {
		assert(user->status == STATUS_WAIT_DNS);
	}

	if (!ent || !ent->h_addr) {
		// resolution completed but there was no IP
		if (user->waiting_addr) {
			// cut resolution delay short
			assert(is_last);
			return socket_handler(fd, AS_TIMEOUT, user);
		} else if (!is_last) {
			return;
		}
		r = SOCKS_REPLY_SERVERROR;
		goto reply_error;
	} else if (!is_last && ent->h_addrtype == AF_INET) {
		// IPv4 resolved first, wait a bit for the IPv6 to resolve
		assert(!user->waiting_addr);
		user->waiting_addr = ent;
		as_set_timeout(ctx, user, HAPPY_EYEBALLS_RESOLUTION_DELAY);
		return;
	}

	struct sockaddr_storage addr;
	sockaddr_from_hostent(&addr, ent, user->remote_port);
	dns_free_hostent(ent);

	// note that the second resolve might still complete in time
	int set_timeout = (is_last && !user->waiting_addr) ? config.connect_timeout :
		HAPPY_EYEBALLS_CONN_ATTEMPT_DELAY;
	r = start_connection_attempt(user, &addr, set_timeout);
	if (r != 0) {
		if (!is_last)
			return;
		r = -r; // flip it around for the error response
		goto reply_error;
	}
	return;

reply_error:
	send_socks_error(fd, r);

	delete_state(user, DEL_CLOSE | DEL_RECURSE);
}

static void handler_dns(int fd, int event)
{
	int request_id;
	struct hostent *ent;
	while (dns_read_response(&request_id, &ent)) {
		struct proto_state *user = request_table_retrieve(request_id);
		if (!user)
			continue;
		process_dns_response(user, request_id, ent);
		request_table_unset(request_id);
	}
}

/**/

static void handler_expect_auth(int fd, int event, struct proto_state *user)
{
	if (event & (AS_TIMEOUT | AS_POLLERR))
		goto exit_error;

	char buf[20];
	int r = recv(fd, buf, sizeof(buf), 0);
	if (r == -1) {
		perror("recv");
		goto exit_error;
	} else if (r < 2) {
		goto exit_error;
	}

	if (buf[0] != SOCKS_VERSION)
		goto exit_error;
	int auth_methods = buf[1];
	if (r < auth_methods + 2)
		goto exit_error;
	bool ok = memchr(&buf[2], SOCKS_AUTH_NONE, auth_methods) != NULL;

	buf[0] = SOCKS_VERSION;
	buf[1] = ok ? SOCKS_AUTH_NONE : SOCKS_AUTH_NO_ACCEPTABLE;
	send(fd, buf, 2, 0);

	if (!ok)
		goto exit_error;
	user->status = STATUS_EXPECT_REQUEST;
	return;

exit_error:
	delete_state(user, DEL_CLOSE);
}

static void handler_expect_request(int fd, int event, struct proto_state *user)
{
	if (event & (AS_TIMEOUT | AS_POLLERR))
		return delete_state(user, DEL_CLOSE);

	int r;
	char buf[300];

	r = recv(fd, buf, sizeof(buf), 0);
	if (r == -1) {
		perror("recv");
		goto exit_error;
	} else if (r < 4) {
		goto exit_error;
	}

	if (buf[0] != SOCKS_VERSION)
		goto exit_error;
	if (buf[1] != SOCKS_CMD_CONNECT) {
		r = SOCKS_REPLY_CMDNOTSUPP;
		goto reply_error;
	}

	// parse the address given to us
	struct sockaddr_storage addr;
	switch (buf[3]) {
		case SOCKS_ATYPE_IPV4: {
			struct sockaddr_in *a = (struct sockaddr_in*) &addr;
			a->sin_family = AF_INET;
			if (r < 10)
				goto exit_error;
			memcpy(&a->sin_addr.s_addr, &buf[4], 4);
			memcpy(&a->sin_port, &buf[8], 2);
			break;
		}
		case SOCKS_ATYPE_IPV6: {
			struct sockaddr_in6 *a = (struct sockaddr_in6*) &addr;
			a->sin6_family = AF_INET6;
			if (r < 22)
				goto exit_error;
			memcpy(&a->sin6_port, &buf[20], 2);
			memcpy(&a->sin6_addr.s6_addr, &buf[4], 16);
			break;
		}
		case SOCKS_ATYPE_DOMAIN: {
			int host_len = buf[4];
			if (r < 5 + host_len + 2)
				goto exit_error;
			// save the port for later
			memcpy(&user->remote_port, &buf[5 + host_len], 2);

			buf[5 + host_len] = '\0';
			const char *hostname = &buf[5];
#ifndef NDEBUG
			printf("\"%s\"\n", hostname);
#endif

			// see if we can parse the hostname as IP literal
			r = inet_pton(AF_INET, hostname, &((struct sockaddr_in*) &addr)->sin_addr);
			if (r == 1) {
				addr.ss_family = AF_INET;
				((struct sockaddr_in*) &addr)->sin_port = user->remote_port;
				goto direct;
			}
			r = inet_pton(AF_INET6, hostname, &((struct sockaddr_in6*) &addr)->sin6_addr);
			if (r == 1) {
				addr.ss_family = AF_INET6;
				((struct sockaddr_in6*) &addr)->sin6_port = user->remote_port;
				goto direct;
			}

			// start dns request(s) for the hostname
			bool ipv6 = is_ipv6_connectable();
			if (ipv6)
				user->dns_request_ids[0] = request_table_allocate(user);
			user->dns_request_ids[1] = request_table_allocate(user);
			if ((ipv6 && dns_request(user->dns_request_ids[0], hostname, true) == -1) ||
				dns_request(user->dns_request_ids[1], hostname, false) == -1) {
				r = SOCKS_REPLY_SERVERROR;
				goto reply_error;
			}

			// wait for dns request completion
			as_set_timeout(ctx, user, config.connect_timeout / 2);
			as_set_events(ctx, user, 0);
			user->status = STATUS_WAIT_DNS;
			return;
		}
		default:
			r = SOCKS_REPLY_ATYPENOTSUPP;
			goto reply_error;
	}

direct:
	// note that this code path is only entered for literal ip addresses

#ifndef NDEBUG
	{
		char ipbuf[50];
		if (addr.ss_family == AF_INET6)
			inet_ntop(AF_INET6, &((struct sockaddr_in6*) &addr)->sin6_addr, ipbuf, sizeof(ipbuf));
		else
			inet_ntop(AF_INET, &((struct sockaddr_in*) &addr)->sin_addr, ipbuf, sizeof(ipbuf));
		printf("lit %s\n", ipbuf);
	}
#endif

	as_set_events(ctx, user, 0);

	r = start_connection_attempt(user, &addr, config.connect_timeout);
	if (r != 0) {
		r = -r; // flip it around for the error response
		goto reply_error;
	}
	return;

reply_error:
	send_socks_error(fd, r);
exit_error:
	delete_state(user, DEL_CLOSE | DEL_RECURSE);
}

static void handler_wait_dns(int fd, int event, struct proto_state *user)
{
	if (event & AS_POLLERR)
		goto exit_error;

	if (event != AS_TIMEOUT)
		return;

	int r;
	if (!user->waiting_addr) {
		// resolution timed out entirely
		r = SOCKS_REPLY_SERVERROR;
		goto reply_error;
	}

	// happy eyeballs resolution delay expired, start with the address we have
	struct sockaddr_storage addr;
	sockaddr_from_hostent(&addr, user->waiting_addr, user->remote_port);
	dns_free_hostent(user->waiting_addr);
	user->waiting_addr = NULL;

	// note that the second resolve might still complete in time
	r = start_connection_attempt(user, &addr, HAPPY_EYEBALLS_CONN_ATTEMPT_DELAY);
	if (r != 0)
		assert(user->dns_request_ids[0] != -1 || user->dns_request_ids[1] != -1);
	return;

reply_error:
	send_socks_error(fd, r);
exit_error:
	delete_state(user, DEL_CLOSE | DEL_RECURSE);
}

static void handler_wait_connection(int fd, int event, struct proto_state *user)
{
	if (event & AS_POLLERR)
		goto exit_error;

	if (event != AS_TIMEOUT)
		return;
	int r;

	if (user->waiting_addr) {
		// connection attempt delay expired so start the second one
		struct sockaddr_storage addr;
		sockaddr_from_hostent(&addr, user->waiting_addr, user->remote_port);
		dns_free_hostent(user->waiting_addr);
		user->waiting_addr = NULL;

#ifndef NDEBUG
		printf("starting second connect\n");
#endif
		r = start_connection_attempt(user, &addr, config.connect_timeout);
		if (r != 0) {
			r = -r; // flip it around for the error response
			goto reply_error;
		}
		return;
	} else if (user->dns_request_ids[0] != -1 || user->dns_request_ids[1] != -1) {
		// we're still waiting for the second resolve
		user->dns_overdue = 1;
		as_set_timeout(ctx, user, config.connect_timeout / 2);
		return;
	}

	// both connection attempts timed out
	r = SOCKS_REPLY_HOSTUNREACH;

reply_error:
	send_socks_error(fd, r);
exit_error:
	delete_state(user, DEL_CLOSE | DEL_RECURSE);
}

/**/

static void handler_outgoing_connection(int fd, int event, struct proto_state *user)
{
	char buf[30];
	struct proto_state *parent = user->parent_state;
	int clientfd = as_get_fd(parent);

	const bool is_last = !parent->waiting_addr &&
		(!parent->child_states[0] || !parent->child_states[1]) &&
		parent->dns_request_ids[0] == -1 && parent->dns_request_ids[1] == -1;

	// connection failed
	if (event & AS_POLLERR) {
		if (!is_last) {
			// another attempt is still active, don't reply with error yet
			int i = parent->child_states[0] == user ? 0 : 1;
			delete_state(user, DEL_CLOSE);
			parent->child_states[i] = NULL;
			if (parent->waiting_addr)
				// start the second request early
				socket_handler(clientfd, AS_TIMEOUT, parent);
			return;
		}

		int error = 0, r;
		socklen_t optlen = sizeof(int);
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &optlen);
		r = errno_to_socks_error(error);

		// send error message
		send_socks_error(clientfd, r);
		goto delete;
	}

	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	int r = getsockname(fd, (struct sockaddr*) &addr, &addrlen);
	if (r == -1) {
		// doesn't really matter
		memset(&addr, 0, sizeof(struct sockaddr_in));
		addr.ss_family = AF_INET;
	}

	// send success message
	buf[0] = SOCKS_VERSION;
	buf[1] = SOCKS_REPLY_SUCCESS;
	buf[2] = 0;
	if (addr.ss_family == AF_INET) {
		struct sockaddr_in *a = (struct sockaddr_in*) &addr;
		buf[3] = SOCKS_ATYPE_IPV4;
		memcpy(&buf[4], &a->sin_addr.s_addr, 4);
		memcpy(&buf[8], &a->sin_port, 2);
		r = 10;
	} else if (addr.ss_family == AF_INET6) {
		struct sockaddr_in6 *a = (struct sockaddr_in6*) &addr;
		buf[3] = SOCKS_ATYPE_IPV6;
		memcpy(&buf[4], &a->sin6_addr.s6_addr, 16);
		memcpy(&buf[20], &a->sin6_port, 2);
		r = 22;
	}
	send(clientfd, buf, r, 0);

	// clean states up and pass sockets to forwarder
	{
		int i = parent->child_states[0] == user ? 1 : 0;
		delete_state(parent->child_states[i], DEL_CLOSE);
		parent->child_states[i] = NULL;
		delete_state(user, DEL_RECURSE);
	}

	r = forwarder_pass(clientfd, fd);
	if (r == -1) {
		close(clientfd);
		close(fd);
	}
	return;

delete:
	delete_state(user, DEL_CLOSE | DEL_RECURSE);
}

static void socket_handler(int fd, int event, void *_user)
{
	struct proto_state *user = (struct proto_state*) _user;
	//printf("socket_handler(%d, %d) status=%d\n", fd, event, user->status);
	switch (user->status) {
		case STATUS_LISTENER:
			return handler_listener(fd, event);
		case STATUS_DNS:
			return handler_dns(fd, event);

		case STATUS_EXPECT_AUTH:
			return handler_expect_auth(fd, event, user);
		case STATUS_EXPECT_REQUEST:
			return handler_expect_request(fd, event, user);
		case STATUS_WAIT_DNS:
			return handler_wait_dns(fd, event, user);
		case STATUS_WAIT_CONNECTION:
			return handler_wait_connection(fd, event, user);

		case STATUS_OUTGOING_CONNECTION:
			return handler_outgoing_connection(fd, event, user);
		default:
			break;
	}
}
