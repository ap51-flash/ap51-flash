/* SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: Antonio Quartulli <a@unstable.cc>
 */

#ifndef __AP51_FLASH_ROUTER_NETCONSOLE_H__
#define __AP51_FLASH_ROUTER_NETCONSOLE_H__

#define IPPORT_NETCONSOLE 6666

struct node;

extern const struct router_type ap121f;

void handle_netconsole_packet(const char *packet_buff, int packet_buff_len,
			      struct node *node);

#endif /* __AP51_FLASH_ROUTER_NETCONSOLE_H__ */
