/*
 * SPDX-FileCopyrightText: Marek Lindner <mareklindner@neomailbox.ch>
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
 */

#ifndef __AP51_FLASH_SOCKET_H__
#define __AP51_FLASH_SOCKET_H__

void socket_print_all_ifaces(void);
char *socket_find_iface_by_index(const char *iface_number);
int socket_open(const char *iface);
int socket_read(char *packet_buff, int packet_buff_len, int *sleep_sec,
		int *sleep_usec);
int socket_write(const char *buff, int len);
void socket_close(const char *iface);

#endif /* __AP51_FLASH_SOCKET_H__ */
