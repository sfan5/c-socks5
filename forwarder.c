#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>

#include "forwarder.h"
#include "async.h"
#include "main.h"

// If we start seeing data chunks over this size assume that bulk transfer
// is happening and disable NODELAY
#define NODELAY_MIN_SIZE 512

struct fwd_args {
	int client_sock, remote_sock;
};

struct fwd_state {
	struct fwd_state *other_state;
	char *waiting_send; // buffer waiting to be sent to our socket
	size_t waiting_send_size;
	bool
		has_timeout : 1, // is the timeout set on our state or the other?
		nodelay_enabled : 1; // is nodelay enabled on the other socket? (that's where we send to)
};

static struct as_context *ctx;
static char *receive_buffer;
static size_t receive_size;
static int wakeup_pipe[2];

static void socket_handler(int fd, int event, void *user);
static void *mainloop(void*);

int forwarder_init(void)
{
	ctx = as_create();
	if (!ctx)
		return -1;

	if (pipe(wakeup_pipe) == -1)
		return -1;
	if (!as_add_fd(ctx, wakeup_pipe[0], AS_POLLIN, 0, ""))
		return -1;

	// size our receive buffer optimally so that ideally
	// everything can be handed right back to the kernel
	receive_size = 0;
	{
		int sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock != -1) {
			int tmp = 0;
			socklen_t optlen = sizeof(int);
			if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &tmp, &optlen) == 0 && tmp > 0)
				receive_size = tmp;
			close(sock);
		}
	}
	if (!receive_size)
		receive_size = 8 * sysconf(_SC_PAGESIZE);
	receive_buffer = calloc(1, receive_size);
	if (!receive_buffer)
		return -1;

	pthread_t t;
	if (pthread_create(&t, NULL, mainloop, NULL) == -1)
		return -1;
	pthread_detach(t);
	return 0;
}

int forwarder_pass(int client_sock, int remote_sock)
{
	// We cannot call as_add_fd from this thread, so push the stuff we need through a pipe
	struct fwd_args a;
	a.client_sock = client_sock;
	a.remote_sock = remote_sock;

	if (write(wakeup_pipe[1], &a, sizeof(a)) != sizeof(a))
		abort();

	return 0;
}

static void wakeup_handler(int fd, int event)
{
	struct fwd_args a;
	if (read(fd, &a, sizeof(a)) != sizeof(a))
		abort();

	// Most protocols probably benefit from speedy set-up, so default nodelay enabled
	// (client_sock already has it set)
	const int opt = 1;
	setsockopt(a.remote_sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(int));

	// create states for the two sockets
	struct fwd_state new = {0};
	new.nodelay_enabled = 1;
	new.has_timeout = 1;
	void *new_state = as_add_fd(ctx, a.client_sock, AS_POLLIN, sizeof(new), &new);
	if (!new_state) {
		close(a.client_sock);
		close(a.remote_sock);
		return;
	}
	as_set_timeout(ctx, new_state, config.idle_timeout * 1000);

	new.other_state = new_state;
	new.has_timeout = 0;
	void *new_state2 = as_add_fd(ctx, a.remote_sock, AS_POLLIN, sizeof(new), &new);
	if (!new_state2) {
		as_del_fd(ctx, new_state);
		close(a.client_sock);
		close(a.remote_sock);
		return;
	}

	// fully link the two
	((struct fwd_state*) new_state)->other_state = new_state2;
}

static void socket_handler(int fd, int event, void *_user)
{
	if (fd == wakeup_pipe[0])
		return wakeup_handler(fd, event);

	struct fwd_state *user = (struct fwd_state*) _user;
	const int other_fd = as_get_fd(user->other_state);

	//if (event & (~AS_POLLIN))
	//	printf("socket_handler(%d, %d) <-> %d\n", fd, event, other_fd);

	// timeout / error
	if (event & AS_TIMEOUT)
		goto delete;
	if (event & AS_POLLERR) {
		int error = 0;
		socklen_t optlen = sizeof(int);
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &optlen);
		printf("pollerr: %s\n", strerror(error));
		goto delete;
	}

	// there is data to be sent and we can send it now
	if (event == AS_POLLOUT) {
		int r = send(fd, user->waiting_send, user->waiting_send_size, 0);
		//printf("writable, delivering %ld %s\n", user->waiting_send_size,
		//	(r >= user->waiting_send_size) ? "ok" : "PARTIAL");
		if (r < 0) {
			perror("send");
			goto delete;
		} else if (r < user->waiting_send_size) {
			size_t keep_size = user->waiting_send_size - r;
			memmove(user->waiting_send, &user->waiting_send[r], keep_size);
			user->waiting_send_size = keep_size;
			return;
		}
		free(user->waiting_send);
		user->waiting_send = NULL;

		// return normal event state
		as_set_events(ctx, user, AS_POLLIN);
		as_set_events(ctx, user->other_state, AS_POLLIN);

		return;
	}

	// incoming data: event == AS_POLLIN
	int r = recv(fd, receive_buffer, receive_size, 0);
	if (r == 0) {
		// EOF
		goto delete;
	} else if (r < 0) {
		perror("recv");
		goto delete;
	}

	size_t send_size = r;

	// decide whether NODELAY should be enabled
	if (send_size >= NODELAY_MIN_SIZE && user->nodelay_enabled) {
#ifndef NDEBUG
		printf("(%d -> %d) nodelay off\n", fd, other_fd);
#endif
		int opt = 0;
		setsockopt(other_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(int));
		user->nodelay_enabled = false;
	}

	size_t delivered_size;
	r = send(other_fd, receive_buffer, send_size, 0);
	if (r < 0) {
		if (errno == EWOULDBLOCK) {
			// no buffer space available
			delivered_size = 0;
		} else {
			perror("send");
			goto delete;
		}
	} else {
		// partial send
		delivered_size = r;
	}

	// rearm timeout
	as_set_timeout(ctx, user->has_timeout ? user : user->other_state, config.idle_timeout * 1000);
	if (delivered_size >= send_size)
		return;

	// keep a copy of the unsent data
	size_t keep_size = send_size - delivered_size;
	char *buffer = calloc(1, keep_size);
	if (!buffer)
		goto delete;
	memcpy(buffer, &receive_buffer[delivered_size], keep_size);
	user->other_state->waiting_send = buffer;
	user->other_state->waiting_send_size = keep_size;

	// ..and wait for the socket to become writable again
	//printf("waiting for writable (%ld)\n", keep_size);
	as_set_events(ctx, user, 0);
	as_set_events(ctx, user->other_state, AS_POLLOUT);

	return;

delete:
#ifndef NDEBUG
	printf("deleting %d <-> %d\n", fd, other_fd);
#endif
	as_del_fd(ctx, user->other_state);
	as_del_fd(ctx, user);
	close(fd);
	close(other_fd);
}

static void *mainloop(void *unused)
{
#if !defined(NDEBUG) && defined(__GLIBC__)
	printf("forwarder tid: %d\n", gettid());
#endif
	while (1) {
		as_poll(ctx, socket_handler);
	}
	return NULL;
}

