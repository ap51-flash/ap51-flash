/* SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: Marek Lindner <mareklindner@neomailbox.ch>
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
