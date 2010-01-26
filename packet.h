/*
 * Copyright (C) open-mesh inc
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

#include "ap51-flash.h"

#define TFTP_SRC_PORT 13337
#define ARP_LEN (sizeof(struct ether_header) + sizeof(struct ether_arp))
#define TFTP_BASE_LEN (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr))
#define TCP_BASE_LEN (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr))

extern struct ether_header *ethhdr;
extern struct ether_arp *arphdr;
extern struct iphdr *iphdr;
extern struct udphdr *udphdr;
extern void *tftp_data;

void arp_packet_init(void);
void arp_packet_send(void);
void tftp_transfer(void);
