/* SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: Marek Lindner <mareklindner@neomailbox.ch>
 */

#ifndef __AP51_FLASH_ROUTER_NETBOOT_SERVER_H__
#define __AP51_FLASH_ROUTER_NETBOOT_SERVER_H__

#include "router_types.h"

struct oui_entry {
	uint8_t mac[3];
};

struct router_netboot_server {
	struct router_type router_type;
	struct {
		unsigned int server_ip;
		unsigned int range_min;
		unsigned int range_max;
	} bootp;
	struct oui_entry *oui_entries;
	size_t oui_entries_num;
};

extern const struct router_netboot_server mikrotik;

#endif /* __AP51_FLASH_ROUTER_NETBOOT_SERVER_H__ */
