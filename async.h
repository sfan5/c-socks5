#pragma once

#include <stddef.h>

struct as_context;

typedef void (*as_handler_fn)(int, int, void*);
// int fd, int event, void *user

#define AS_POLLIN  1
#define AS_POLLOUT 2
#define AS_TIMEOUT 4
#define AS_POLLERR 8

struct as_context *as_create(void);

void *as_add_fd(struct as_context *, int fd, int events, size_t usersize, const void *userinit);

int as_del_fd(struct as_context *, void *user);

int as_poll(struct as_context *, as_handler_fn handler);

int as_get_fd(void *user);

int as_set_events(struct as_context *, void *user, int events);

int as_set_timeout(struct as_context *, void *user, int timeout_ms);

void as_destroy(struct as_context *);
