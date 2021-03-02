#pragma once

#include <stdbool.h>

int dns_init(void);

int dns_get_readable_fd(void);

int dns_request(int request_id, const char *name, bool aaaa);

int dns_read_response(int *request_id, struct hostent **result);

void dns_free_hostent(struct hostent *result);
