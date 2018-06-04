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

static const unsigned int ap121f_ip = 3232235777UL; /* 192.168.1.1 */
static const unsigned int my_ip = 3232235778UL;  /* 192.168.1.2 */

static const uint8_t zero_mac[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t ap121f_mac[] = { 0x00, 0x03, 0x7f, 0x09, 0x0b, 0xad };

enum netconsole_state {
	NETCONSOLE_STATE_WAITING,
	NETCONSOLE_STATE_STARTED,
	NETCONSOLE_STATE_DONE,
	NETCONSOLE_STATE_RESET,
};

struct netconsole_priv {
	enum netconsole_state state;
};

static int ap121f_detect_main(void (*priv)__attribute__((unused)),
			      const char *packet_buff, int packet_buff_len)
{
	struct ether_arp *arphdr;
	int ret = 0;

	if (!len_check(packet_buff_len, sizeof(struct ether_arp), "ARP"))
		goto out;

	arphdr = (struct ether_arp *)packet_buff;
	if (arphdr->ea_hdr.ar_op != htons(ARPOP_REQUEST))
		goto out;

	if (*((unsigned int *)arphdr->arp_spa) != htonl(ap121f_ip))
		goto out;

	if (*((unsigned int *)arphdr->arp_tpa) != htonl(my_ip))
		goto out;

	if (memcmp(arphdr->arp_sha, ap121f_mac, ETH_ALEN))
		goto out;

	if (memcmp(arphdr->arp_tha, zero_mac, ETH_ALEN))
		goto out;

	ret = 1;

out:
	return ret;
}

static void netconsole_detect_post(struct node *node, const char *packet_buff,
				   int packet_buff_len)
{
	struct netconsole_priv *priv = node->router_priv;
	struct ether_arp *arphdr;

	if (!len_check(packet_buff_len, sizeof(struct ether_arp), "ARP"))
		goto out;

	arphdr = (struct ether_arp *)packet_buff;

	node->flash_mode = FLASH_MODE_NETCONSOLE;
	node->his_ip_addr = load_ip_addr(arphdr->arp_spa);
	node->our_ip_addr = load_ip_addr(arphdr->arp_tpa);
	priv->state = NETCONSOLE_STATE_WAITING;

out:
	return;
}

const struct router_type ap121f = {
	.desc = "Alfa Network AP121F",
	.detect_main = ap121f_detect_main,
	.detect_post = netconsole_detect_post,
	.image = &img_uboot,
	.priv_size = sizeof(struct netconsole_priv),
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
