#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "main.h"

static void strip(char *buf);
static inline bool parse_int(int *dst, const char *s);
static bool parse_address(struct sockaddr_storage *dst, const char *s, bool port);
static void append_addr_list(struct config_addr_list **l, const struct sockaddr_storage *addr);
static int read_config(FILE *f);

int read_args(int argc, char *argv[])
{
	// defaults
	memset(&config, 0, sizeof(config));
	config.hello_timeout = 5 * 1000;
	config.connect_timeout = 15 * 1000;
	config.idle_timeout = 3600;
	config.bind_address4.s_addr = INADDR_ANY;
	config.bind_address6 = (struct in6_addr) IN6ADDR_ANY_INIT;

	// read command line arguments
	int argi = 1;
	while (argi < argc) {
		const char *s = argv[argi++];
		if (!strcmp(s, "-h") || !strcmp(s, "--help")) {
			return -2;
		} else if (!strcmp(s, "-c") && argi < argc) {
			// parse config file
			FILE *f = fopen(argv[argi++], "r");
			if (!f) {
				perror("fopen");
				return -1;
			}
			if (read_config(f) == -1)
				return -1;
			fclose(f);
		} else if (!strcmp(s, "-b") && argi < argc) {
			const char *arg = argv[argi++];
			struct sockaddr_storage addr;
			if (!parse_address(&addr, arg, true)) {
				fprintf(stderr, "couldn't parse address \"%s\"\n\n", arg);
				return -2;
			}
			append_addr_list(&config.bind_listener, &addr);
		} else if (!strcmp(s, "--dns") && argi < argc) {
			const char *arg = argv[argi++];
			struct sockaddr_storage addr;
			if (!parse_address(&addr, arg, false)) {
				fprintf(stderr, "couldn't parse address \"%s\"\n\n", arg);
				return -2;
			}
			append_addr_list(&config.dns_server, &addr);
		} else {
			fprintf(stderr, "unrecognized %s \"%s\"%s\n\n",
				s[0] == '-' ? "switch" : "argument", s,
				s[0] == '-' ? " (or argument missing)" : "");
			return -2;
		}
	}

	// defaults (part 2)
	if (!config.bind_listener) {
		struct sockaddr_storage addr = {0};
		memcpy(&addr, &(struct sockaddr_in) {
			.sin_family = AF_INET,
			.sin_addr = {INADDR_ANY},
			.sin_port = htons(1080),
		}, sizeof(struct sockaddr_in));
		append_addr_list(&config.bind_listener, &addr);
		memcpy(&addr, &(struct sockaddr_in6) {
			.sin6_family = AF_INET6,
			.sin6_addr = IN6ADDR_ANY_INIT,
			.sin6_port = htons(1080),
		}, sizeof(struct sockaddr_in6));
		append_addr_list(&config.bind_listener, &addr);
	}

	return 0;
}

void free_addr_list(struct config_addr_list *list)
{
	for (struct config_addr_list *c = list; c; ) {
		struct config_addr_list *next = c->next;
		free(c);
		c = next;
	}
}

#define PARSE_ERROR(fmt, ...) fprintf(stderr, "On line %d: " fmt ".\n", lineno, __VA_ARGS__)

static int read_config(FILE *f)
{
	char line[512];
	int lineno = 0;

	while (fgets(line, sizeof(line), f)) {
		lineno++;
		strip(line);
		if (!line[0] || line[0] == '#')
			continue;

		char *k, *v;
		k = line;
		v = strchr(line, '=');
		if (!v) {
			PARSE_ERROR("no equals sign found%s", "");
			return -1;
		}

		*v = '\0';
		v++;
		strip(k);
		strip(v);

		if (!strcmp(k, "bind")) {
			struct sockaddr_storage addr;
			if (!parse_address(&addr, v, true)) {
				PARSE_ERROR("couldn't parse address \"%s\"", v);
				return -1;
			}
			append_addr_list(&config.bind_listener, &addr);
		} else if (!strcmp(k, "connect-timeout")) {
			if (!parse_int(&config.connect_timeout, v)) {
				PARSE_ERROR("couldn't parse integer \"%s\"", v);
				return -1;
			}
		} else if (!strcmp(k, "dns")) {
			struct sockaddr_storage addr;
			if (!parse_address(&addr, v, false)) {
				PARSE_ERROR("couldn't parse address \"%s\"", v);
				return -1;
			}
			append_addr_list(&config.dns_server, &addr);
		} else if (!strcmp(k, "hello-timeout")) {
			if (!parse_int(&config.hello_timeout, v)) {
				PARSE_ERROR("couldn't parse integer \"%s\"", v);
				return -1;
			}
		} else if (!strcmp(k, "idle-timeout")) {
			if (!parse_int(&config.idle_timeout, v)) {
				PARSE_ERROR("couldn't parse integer \"%s\"", v);
				return -1;
			}
		} else if (!strcmp(k, "out-bind-address")) {
			struct sockaddr_storage addr;
			if (!parse_address(&addr, v, false)) {
				PARSE_ERROR("couldn't parse address \"%s\"", v);
				return -1;
			}
			if (addr.ss_family == AF_INET)
				config.bind_address4 = ((struct sockaddr_in*) &addr)->sin_addr;
			else
				config.bind_address6 = ((struct sockaddr_in6*) &addr)->sin6_addr;
		} else if (!strcmp(k, "out-bind-interface")) {
			snprintf(config.bind_interface, sizeof(config.bind_interface), "%s", v);
		} else {
			PARSE_ERROR("key \"%s\" not recognized", k);
			return -1;
		}
	}

	return 0;
}

#undef PARSE_ERROR

#define IS_WHITESPACE(c) (c == '\t' || c == '\r' || c == '\n' || c == ' ')

static void strip(char *buf)
{
	int i = 0;
	while (IS_WHITESPACE(buf[i]))
		i++;
	if (i > 0)
		memmove(buf, &buf[i], strlen(buf) + 1 - i);

	char *p = buf + strlen(buf) - 1;
	while (p > buf && IS_WHITESPACE(*p))
		p--;
	*(p + 1) = '\0';
}

#undef IS_WHITESPACE

static inline bool parse_int(int *dst, const char *s)
{
	char *endptr;
	long int n = strtol(s, &endptr, 0);
	if (endptr == s || *endptr != '\0')
		return false;
	*dst = n;
	return true;
}

static bool parse_address(struct sockaddr_storage *dst, const char *_s, bool port)
{
	char s[64] = {0};
	const char *namestr, *portstr = NULL;

	strncpy(s, _s, sizeof(s) - 1);

	if (port) {
		char *p = strrchr(s, ':');
		if (!p)
			return false;
		if (p > s && *(p - 1) == ']' && *s == '[') {
			namestr = s + 1;
			*(p - 1) = '\0';
		} else if (strchr(s, ':') != p) {
			return false; // IPv6 but addr is not enclosed in []
		} else {
			namestr = s;
			*p = '\0';
		}
		portstr = p + 1;
	} else {
		namestr = s;
	}

	int r = inet_pton(AF_INET, namestr, &((struct sockaddr_in*) dst)->sin_addr);
	if (r == 1) {
		dst->ss_family = AF_INET;
		goto ok;
	}
	r = inet_pton(AF_INET6, namestr, &((struct sockaddr_in6*) dst)->sin6_addr);
	if (r == 1) {
		dst->ss_family = AF_INET6;
		goto ok;
	}
	return false;

ok:
	if (port) {
		int n;
		if (!parse_int(&n, portstr))
			return false;
		if (dst->ss_family == AF_INET)
			((struct sockaddr_in*) dst)->sin_port = htons(n);
		else
			((struct sockaddr_in6*) dst)->sin6_port = htons(n);
	}

	return true;
}

static void append_addr_list(struct config_addr_list **l, const struct sockaddr_storage *addr)
{
	while (*l)
		l = &(*l)->next;

	*l = calloc(1, sizeof(struct config_addr_list));
	memcpy(&(*l)->addr, addr, sizeof(struct sockaddr_storage));
}
