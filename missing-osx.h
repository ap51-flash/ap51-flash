/*
 * Copyright (C) Open Mesh, Inc.
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

#ifndef __MISSING_OSX_H__
#define __MISSING_OSX_H__

#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETHERTYPE_ARP 0x0806
#define ARPOP_REQUEST 1
#define ARPOP_REPLY   2
#define ETH_P_IP       0x0800          /* Internet Protocol packet     */
#define ICMP_DEST_UNREACH  3
#define IPPORT_TFTP 69

struct iphdr {
	unsigned int ihl:4;
	unsigned int version:4;
	u_int8_t tos;
	u_int16_t tot_len;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t check;
	u_int32_t saddr;
	u_int32_t daddr;
};

struct udphdr {
	u_int16_t source;
	u_int16_t dest;
	u_int16_t len;
	u_int16_t check;
};

#endif /* __MISSING_OSX_H__ */
