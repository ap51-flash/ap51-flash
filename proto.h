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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef __AP51_FLASH_PROTO_H__
#define __AP51_FLASH_PROTO_H__

#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct node;

#define NET_IP_ALIGN 2

enum tcp_status {
	TCP_STATUS_SYN_SENT,
	TCP_STATUS_ESTABLISHED,
	TCP_STATUS_TELNET_READY,
};

struct tcp_state {
	char *packet_buff;
	enum tcp_status status;
	unsigned int his_seq;
	unsigned int his_ack_seq;
	unsigned int his_last_len;
	unsigned int my_seq;
	unsigned int my_ack_seq;
};

struct image_state {
	int fd;
	unsigned int bytes_sent;
	unsigned int file_size;
	unsigned int total_bytes_sent;
	unsigned int flash_size;
	unsigned int offset;
	unsigned short last_packet_size;
	unsigned short block_acked;
	unsigned short block_sent;
	/* flags */
	unsigned char count_globally:1;
};

int arp_req_send(const uint8_t *src_mac, const uint8_t *dst_mac,
		 unsigned int src_ip, unsigned int dst_ip);
int tftp_init_upload(struct node *node);
int netconsole_init_upload(struct node *node);
void telnet_handle_connection(struct node *node);
int telnet_send_cmd(struct node *node, const char *cmd);
void handle_eth_packet(char *packet_buff, int packet_buff_len);
int proto_init(void);
void proto_free(void);

static inline void store_ip_addr(void *dst, uint32_t ip)
{
	memcpy(dst, &ip, sizeof(ip));
}

static inline uint32_t load_ip_addr(void *src)
{
	uint32_t ip;

	memcpy(&ip, src, sizeof(ip));

	return ip;
}

#if defined(DEBUG)
static inline int len_check(int buff_len, int req_len, char *desc)
#else
static inline int len_check(int buff_len, int req_len,
			    char (*desc)__attribute__((unused)))
#endif
{
	if (buff_len >= req_len)
		return 1;

#if defined(DEBUG)
	fprintf(stderr, "Warning - dropping received %s packet as it is smaller than expected: %i (required: %i)\n",
		desc, buff_len, req_len);
#endif
	return 0;
}

#endif /* __AP51_FLASH_PROTO_H__ */
