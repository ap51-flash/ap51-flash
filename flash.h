/*
 * Copyright (C) Marek Lindner
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 3 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 * SPDX-License-Identifier: GPL-3.0+
 * License-Filename: LICENSES/preferred/GPL-3.0
 */

#ifndef __AP51_FLASH_FLASH_H__
#define __AP51_FLASH_FLASH_H__

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "proto.h"

enum flash_mode {
	FLASH_MODE_UKNOWN,
	FLASH_MODE_REDBOOT,
	FLASH_MODE_TFTP_SERVER,
	FLASH_MODE_TFTP_CLIENT,
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

static inline bool is_zero_ether_addr(const uint8_t *mac)
{
	return !(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]);
}

static inline void ether_addr_copy_mask(uint8_t *dst, const uint8_t *src,
					const uint8_t *mask)
{
	size_t i;

	for (i = 0; i < 6; i++)
		dst[i] = src[i] & mask[i];
}

static inline bool ether_addr_equal_mask(const uint8_t *mac1,
					 const uint8_t *mac2,
					 const uint8_t *mask)
{
	uint8_t masked1[6];
	uint8_t masked2[6];

	ether_addr_copy_mask(masked1, mac1, mask);
	ether_addr_copy_mask(masked2, mac2, mask);

	return memcmp(masked1, masked2, sizeof(masked1)) == 0;
}

#endif /* __AP51_FLASH_FLASH_H__ */
