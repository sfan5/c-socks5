#pragma once

int forwarder_init(void);

int forwarder_pass(int client_sock, int remote_sock);
