#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>

struct config_addr_list {
	struct sockaddr_storage addr;
	struct config_addr_list *next;
};

struct config_struct {
	struct config_addr_list *bind_listener;
	int hello_timeout; // ms
	int connect_timeout; // ms
	int idle_timeout; // s

	// for outgoing connections:
	struct in_addr bind_address4;
	struct in6_addr bind_address6;
	char bind_interface[IF_NAMESIZE+1];

	struct config_addr_list *dns_server; // (ports not used)
};

extern struct config_struct config;
