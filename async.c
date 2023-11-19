#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#ifndef NDEBUG
#include <assert.h>
#define as_assert(expr) assert(expr)
#else
#define as_assert(expr) ((void)0)
#endif

#include "async.h"

#define EPOLL_MAX_EVENTS 32

struct as_fdentry {
	struct as_fdentry *prev, *next;
	uint64_t timeout;
	int fd;
	char user[];
};

struct as_context {
	struct as_fdentry *first, *last;
	int epoll_fd;

	// event structures used by the thread that runs the event loop
	// this is used to remove/modify pending events that have already been received from epoll
#ifndef NDEBUG
	pthread_t eventloop_thread;
#endif
	struct epoll_event events[EPOLL_MAX_EVENTS];
	int events_count;

	// entry of the list that is currently being iterated
	// this is used to defer modification/deletion of the current entry until it's safe to do
	void *current_entry;
	int want_current_timeout_set;
	int want_current_freed : 1;
};

static inline uint64_t monotonic_ms(void);
static inline struct as_fdentry *entry_from_user(void *user);
static void list_remove_inplace(struct as_context *c, struct as_fdentry *e);
static void list_add_sorted(struct as_context *c, struct as_fdentry *e);
static void cleanup_entry(struct as_context *c, struct as_fdentry *e);
static void entry_set_timeout(struct as_context *c, struct as_fdentry *e, int timeout_ms);

struct as_context *as_create(void)
{
	struct as_context *c = calloc(1, sizeof(struct as_context));
	if (!c)
		return NULL;
	c->epoll_fd = epoll_create(1);
	if (c->epoll_fd == -1) {
		perror("epoll_create");
		free(c);
		return NULL;
	}
	return c;
}

void *as_add_fd(struct as_context *c, int fd, int events, size_t usersize, const void *userinit)
{
	struct as_fdentry *e = calloc(1, sizeof(struct as_fdentry) + usersize);
	if (!e)
		return NULL;
	e->fd = fd;
	memcpy(e->user, userinit, usersize);

	struct epoll_event ev;
	ev.data.ptr = e;
	ev.events = (events & AS_POLLIN) ? EPOLLIN : 0;
	ev.events |= (events & AS_POLLOUT) ? EPOLLOUT : 0;
	if (epoll_ctl(c->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		perror("epoll_ctl");
		free(e);
		return NULL;
	}

	return e->user;
}

int as_del_fd(struct as_context *c, void *user)
{
	struct as_fdentry *e = entry_from_user(user);
	as_assert(c->eventloop_thread == (pthread_t) 0 || pthread_equal(c->eventloop_thread, pthread_self()));

	if (epoll_ctl(c->epoll_fd, EPOLL_CTL_DEL, e->fd, NULL)) {
		perror("epoll_ctl");
		return -1;
	}
	if (e == c->current_entry) {
		// delay cleanup since we can't free the currently iterating entry
		c->want_current_freed = 1;
	} else {
		// delete pending events for this entry (if any)
		for (int i = 1; i < c->events_count; i++) {
			if (c->events[i].data.ptr == e)
				c->events[i].events = 0;
		}

		cleanup_entry(c, e);
	}
	return 0;
}

int as_poll(struct as_context *c, as_handler_fn handler)
{
#ifndef NDEBUG
	c->eventloop_thread = pthread_self();
#endif
	int timeout_in = -1;
	if (c->first) {
		uint64_t now = monotonic_ms();
		timeout_in = now >= c->first->timeout ? 0 : (c->first->timeout - now);
	}

	int ret = epoll_wait(c->epoll_fd, c->events, EPOLL_MAX_EVENTS, timeout_in);
	if (ret == -1) {
		if (errno == EINTR)
			return as_poll(c, handler);
		perror("epoll_wait");
		goto exit;
	}

	// events from epoll
	c->events_count = ret;
	ret = 0;
	for (int n = 0; n < c->events_count; n++) {
		int ev = (c->events[n].events & EPOLLIN) ? AS_POLLIN : 0;
		ev |= (c->events[n].events & EPOLLOUT) ? AS_POLLOUT : 0;
		ev |= (c->events[n].events & EPOLLERR) ? AS_POLLERR : 0;
		if (ev == 0)
			continue;
		ret++;

		struct as_fdentry *e = (struct as_fdentry*) c->events[n].data.ptr;
		handler(e->fd, ev, e->user);
	}
	c->events_count = 0;

	// timeouts
	const uint64_t now = monotonic_ms();
	struct as_fdentry *cur = c->first;
	while (cur) {
		as_assert(cur->timeout);
		if (cur->timeout > now)
			break;
		c->current_entry = cur;
		c->want_current_freed = 0;
		c->want_current_timeout_set = -1000;

		handler(cur->fd, AS_TIMEOUT, cur->user);
		ret++;

		cur = cur->next;
		if (c->want_current_freed)
			cleanup_entry(c, c->current_entry);
		else if (c->want_current_timeout_set != -1000)
			entry_set_timeout(c, c->current_entry, c->want_current_timeout_set);
	}
	c->current_entry = NULL;

	as_assert(ret > 0);
exit:
#ifndef NDEBUG
	c->eventloop_thread = (pthread_t) 0;
#endif
	return ret;
}

int as_get_fd(void *user)
{
	struct as_fdentry *e = entry_from_user(user);
	return e->fd;
}

int as_set_events(struct as_context *c, void *user, int events)
{
	struct as_fdentry *e = entry_from_user(user);
	as_assert(c->eventloop_thread == (pthread_t) 0 || pthread_equal(c->eventloop_thread, pthread_self()));

	struct epoll_event ev;
	ev.data.ptr = e;
	ev.events = (events & AS_POLLIN) ? EPOLLIN : 0;
	ev.events |= (events & AS_POLLOUT) ? EPOLLOUT : 0;
	if (epoll_ctl(c->epoll_fd, EPOLL_CTL_MOD, e->fd, &ev) == -1) {
		perror("epoll_ctl");
		return -1;
	}
	// clamp pending events to this entry by the newly set events
	ev.events |= EPOLLERR;
	for (int i = 1; i < c->events_count; i++) {
		if (c->events[i].data.ptr == e)
			c->events[i].events &= ev.events;
	}
	return 0;
}

int as_set_timeout(struct as_context *c, void *user, int timeout_ms)
{
	struct as_fdentry *e = entry_from_user(user);
	as_assert(c->eventloop_thread == (pthread_t) 0 || pthread_equal(c->eventloop_thread, pthread_self()));

	if (e == c->current_entry)
		// delay modification since we can't move the currently iterating entry
		c->want_current_timeout_set = (timeout_ms < 0) ? -1 : timeout_ms;
	else
		entry_set_timeout(c, e, timeout_ms);
	return 0;
}

void as_destroy(struct as_context *c)
{
	as_assert(c->eventloop_thread == (pthread_t) 0);

	struct as_fdentry *cur = c->first;
	while (cur) {
		void *saved = cur;
		cur = cur->next;
		free(saved);
	}

	close(c->epoll_fd);
	free(c);
}

/**/

static void entry_set_timeout(struct as_context *c, struct as_fdentry *e, int timeout_ms)
{
	uint64_t new_timeout = timeout_ms >= 0 ? (monotonic_ms() + timeout_ms) : 0;

	if (new_timeout == e->timeout)
		return;

	if (e->timeout)
		list_remove_inplace(c, e);
	e->timeout = new_timeout;
	if (new_timeout)
		list_add_sorted(c, e);
}

static void cleanup_entry(struct as_context *c, struct as_fdentry *e)
{
	if (e->timeout)
		list_remove_inplace(c, e);
#ifndef NDEBUG
	memset(e, 0xff, sizeof(struct as_fdentry)); // poison memory
#endif
	free(e);
}

static void list_add_sorted(struct as_context *c, struct as_fdentry *e)
{
	if (!c->last) {
		as_assert(!c->first);
		c->first = c->last = e;
		return;
	}
	as_assert(c->first);

	// see if it belongs to the beginning
	if (e->timeout <= c->first->timeout) {
		e->prev = NULL;
		e->next = c->first;
		c->first->prev = e;
		c->first = e;
		return;
	}

	// iterate backwards to find insertion place
	struct as_fdentry *cur = c->last;
	while (cur->prev) {
		if (cur->timeout <= e->timeout)
			goto insert_after;
		cur = cur->prev;
	}
	if (cur->timeout <= e->timeout) {
insert_after:
		e->prev = cur;
		e->next = cur->next;
		if (!e->next) {
			as_assert(c->last == cur);
			c->last = e;
		} else {
			cur->next->prev = e;
		}
		cur->next = e;
	} else {
		// insert at beginning
		e->prev = NULL;
		e->next = cur;
		cur->prev = e;
		as_assert(c->first == cur);
		c->first = e;
	}
}

static void list_remove_inplace(struct as_context *c, struct as_fdentry *e)
{
	if (e->prev)
		e->prev->next = e->next;
	else
		c->first = e->next;
	if (e->next)
		e->next->prev = e->prev;
	else
		c->last = e->prev;
	e->prev = e->next = NULL;
}

static inline struct as_fdentry *entry_from_user(void *user)
{
	as_assert(user);
	const intptr_t offset = offsetof(struct as_fdentry, user);
	return (struct as_fdentry*) ((intptr_t)user - offset);
}

static inline uint64_t monotonic_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
