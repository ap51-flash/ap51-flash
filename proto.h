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
 */

#include <stdio.h>

int arp_req_send(uint8_t *src_mac, uint8_t *dst_mac, unsigned int src_ip, unsigned int dst_ip);
int tftp_init_upload(struct node *node);
void telnet_handle_connection(struct node *node);
int telnet_send_cmd(struct node *node, char *cmd);
void handle_eth_packet(char *packet_buff, int packet_buff_len);
int proto_init(void);
void proto_free(void);

#if defined(DEBUG)
static inline int len_check(int buff_len, int req_len, char *desc)
#else
static inline int len_check(int buff_len, int req_len, char (*desc)__attribute__((unused)))
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

static inline unsigned short chksum(unsigned short sum, unsigned char *data, unsigned short len)
{
	unsigned short t;
	unsigned char *dataptr, *last_byte;

	dataptr = data;
	last_byte = data + len - 1;

	while (dataptr < last_byte) {
		t = (dataptr[0] << 8) + dataptr[1];
		sum += t;
		if(sum < t)
			sum++;
		dataptr += 2;
	}

	if (dataptr == last_byte) {
		t = (dataptr[0] << 8) + 0;
		sum += t;
		if(sum < t)
			sum++;
	}

	return sum;
}
