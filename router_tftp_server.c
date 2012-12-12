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

#include <stdlib.h>

#include "types.h"
#include "router_tftp_server.h"
#include "proto.h"
#include "flash.h"
#include "router_images.h"

static unsigned int ubnt_ip = 3232235796UL; /* 192.168.1.20 */
static unsigned int my_ip = 3232235801UL;  /* 192.168.1.25 */

struct ubnt_priv {
	int arp_count;
};

static void ubnt_detect_pre(uint8_t *our_mac)
{
	uint8_t bcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	arp_req_send(our_mac, bcast_mac, htonl(my_ip), htonl(ubnt_ip));
}

static int ubnt_detect_main(void *priv, char *packet_buff, int packet_buff_len)
{
	struct ether_arp *arphdr;
	struct ubnt_priv *ubnt_priv = priv;
	int ret = 0;

	if (!len_check(packet_buff_len, sizeof(struct ether_arp), "ARP"))
		goto out;

	arphdr = (struct ether_arp *)packet_buff;
	if (arphdr->ea_hdr.ar_op != htons(ARPOP_REPLY))
		goto out;

	if (*((unsigned int *)arphdr->arp_spa) != htonl(ubnt_ip))
		goto out;

	if (ubnt_priv->arp_count < 20) {
		ubnt_priv->arp_count++;
		goto out;
	}

	ret = 1;

out:
	return ret;
}

static void ubnt_detect_post(struct node *node, char *packet_buff, int packet_buff_len)
{
	struct ether_arp *arphdr;

	if (!len_check(packet_buff_len, sizeof(struct ether_arp), "ARP"))
		goto out;

	arphdr = (struct ether_arp *)packet_buff;

	node->flash_mode = FLASH_MODE_TFTP_SERVER;
	node->his_ip_addr = *((unsigned int *)(arphdr->arp_spa));
	node->our_ip_addr = *((unsigned int *)(arphdr->arp_tpa));

out:
	return;
}

const struct router_type ubnt = {
	.desc = "ubiquiti",
	.detect_pre = ubnt_detect_pre,
	.detect_main = ubnt_detect_main,
	.detect_post = ubnt_detect_post,
	.image = &img_ubnt,
	.priv_size = sizeof(struct ubnt_priv),
};
