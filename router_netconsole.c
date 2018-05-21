/*
 * Copyright (C) Antonio Quartulli
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

#include "router_netconsole.h"

#include <stdint.h>

#include "compat.h"
#include "flash.h"
#include "proto.h"
#include "router_images.h"
#include "router_types.h"

enum netconsole_state {
	NETCONSOLE_STATE_WAITING,
	NETCONSOLE_STATE_STARTED,
	NETCONSOLE_STATE_DONE,
	NETCONSOLE_STATE_RESET,
};

struct netconsole_priv {
	enum netconsole_state state;
};

void handle_netconsole_packet(const char *packet_buff, int packet_buff_len,
			      struct node *node)
{
	struct netconsole_priv *priv = node->router_priv;

#define PROMPT_STR "u-boot> "
#define DONE_STR "DONE!"

//	fprintf(stderr, "received netconsole packet: '%s'\n", packet_buff);

	switch (priv->state) {
	case NETCONSOLE_STATE_WAITING:
		if (packet_buff_len < (int)strlen(PROMPT_STR))
			return;

		if (strncmp(packet_buff, PROMPT_STR, strlen(PROMPT_STR)) != 0)
			return;

		netconsole_init_upload(node);
		priv->state = NETCONSOLE_STATE_STARTED;

		break;
	case NETCONSOLE_STATE_STARTED:
		/* check if we received the completion message */
		if (packet_buff_len < (int)strlen(DONE_STR))
			return;

		if (strncmp(packet_buff, DONE_STR, strlen(DONE_STR)) != 0)
			return;

		fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: flash complete. Rebooting\n",
			node->his_mac_addr[0], node->his_mac_addr[1],
			node->his_mac_addr[2], node->his_mac_addr[3],
			node->his_mac_addr[4], node->his_mac_addr[5],
			node->router_type->desc);

		priv->state = NODE_STATUS_REBOOTED;

#if defined(CLEAR_SCREEN)
		num_nodes_flashed++;
#endif
		break;
	default:
		break;
	}
}
