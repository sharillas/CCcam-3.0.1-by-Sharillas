#ifndef CCCAM3_CLIENT_H
#define CCCAM3_CLIENT_H

#include "cccam3_structs.h"
#include <stdint.h>
#include <time.h>

#define CCCAM3_CLIENT_SLOTS 100

cccam_client_t *cccam_client_create(int socket_fd, struct sockaddr_in *addr);
void cccam_client_destroy(cccam_client_t *client);
cccam_client_t *cccam_client_find_by_socket(int socket_fd);
cccam_client_t *cccam_client_find_by_id(uint32_t client_id);
cccam_client_t *cccam_client_get_by_index(int index);
int cccam_client_get_count(void);
void cccam_client_authenticate(cccam_client_t *client);
void cccam_client_set_hop(cccam_client_t *client, uint8_t hop);
void cccam_client_update_keepalive(cccam_client_t *client);
int cccam_client_is_timeout(cccam_client_t *client, int timeout_seconds);
void cccam_client_close_all(void);

#endif // CCCAM3_CLIENT_H
