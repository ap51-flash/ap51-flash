/* SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: Marek Lindner <marek.lindner@mailbox.org>
 */

#ifndef __AP51_FLASH_FLASH_H__
#define __AP51_FLASH_FLASH_H__

#include <stdint.h>

#include "list.h"
#include "proto.h"

enum flash_mode {
	FLASH_MODE_UKNOWN,
	FLASH_MODE_REDBOOT,
	FLASH_MODE_TFTP_SERVER,
	FLASH_MODE_TFTP_CLIENT,
	FLASH_MODE_NETCONSOLE,
};

enum node_status {
	NODE_STATUS_UNKNOWN,
	NODE_STATUS_DETECTING,
	NODE_STATUS_DETECTED,
	NODE_STATUS_FLASHING,
	NODE_STATUS_FINISHED,
	NODE_STATUS_RESET_SENT,
	NODE_STATUS_REBOOTED,
	NODE_STATUS_NO_FLASH,
};

struct node {
	struct list_head list;
	uint8_t his_mac_addr[6];
	uint8_t our_mac_addr[6];
	uint32_t his_ip_addr;
	uint32_t our_ip_addr;
	enum node_status status;
	enum flash_mode flash_mode;
	struct router_type *router_type;
	struct image_state image_state;
	struct tcp_state tcp_state;
	void *router_priv;
	/* priv declarations are added at runtime */
};

#if defined(CLEAR_SCREEN)
extern int num_nodes_flashed;
#endif

struct node *node_list_get(const uint8_t *mac_addr);
void our_mac_set(struct node *node);
int flash_start(const char *iface);

#endif /* __AP51_FLASH_FLASH_H__ */
