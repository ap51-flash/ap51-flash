/*
 * SPDX-FileCopyrightText: Antonio Quartulli <a@unstable.cc>
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef __AP51_FLASH_ROUTER_NETCONSOLE_H__
#define __AP51_FLASH_ROUTER_NETCONSOLE_H__

#define IPPORT_NETCONSOLE 6666

struct node;

extern const struct router_type ap121f;

void handle_netconsole_packet(const char *packet_buff, int packet_buff_len,
			      struct node *node);

#endif /* __AP51_FLASH_ROUTER_NETCONSOLE_H__ */
