#pragma once

#define DEFAULT_CONFIG_PATH "/etc/c-socks5.conf"

struct config_addr_list;

int read_args(int argc, char *argv[]);

void free_addr_list(struct config_addr_list *list);
