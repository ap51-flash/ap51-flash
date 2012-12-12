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

#include <time.h>
#include <stdlib.h>

#include "types.h"
#include "router_tftp_client.h"
#include "proto.h"
#include "flash.h"
#include "router_images.h"

static unsigned int mr500_ip = 3232260872UL; /* 192.168.99.8 */
static unsigned int om2p_ip = 3232261128UL; /* 192.168.100.8 */

struct mr500_priv {
	time_t start_flash;
};

struct om2p_priv {
	time_t start_flash;
};

static void tftp_client_detect_post(struct node *node, char *packet_buff, int packet_buff_len)
{
	struct ether_arp *arphdr;

	if (!len_check(packet_buff_len, sizeof(struct ether_arp), "ARP"))
		goto out;

	arphdr = (struct ether_arp *)packet_buff;

	node->flash_mode = FLASH_MODE_TFTP_CLIENT;
	node->his_ip_addr = *((unsigned int *)(arphdr->arp_spa));
	node->our_ip_addr = *((unsigned int *)(arphdr->arp_tpa));

out:
	return;
}

void tftp_client_flash_time_set(struct node *node)
{
	struct mr500_priv *mr500_priv;
	struct om2p_priv *om2p_priv;

	if (node->router_type == &mr500) {
		mr500_priv = node->router_priv;
		mr500_priv->start_flash = time(NULL);
	} else if (node->router_type == &om2p) {
		om2p_priv = node->router_priv;
		om2p_priv->start_flash = time(NULL);
	}
}

int tftp_client_flash_completed(struct node *node)
{
	struct mr500_priv *mr500_priv;
	struct om2p_priv *om2p_priv;
	time_t time2flash;

	if (node->router_type == &mr500) {
		mr500_priv = node->router_priv;
		time2flash = mr500_priv->start_flash + 45 + (node->image_state.total_bytes_sent / 65536);
	} else if (node->router_type == &om2p) {
		om2p_priv = node->router_priv;
		time2flash = om2p_priv->start_flash + (node->image_state.total_bytes_sent / 65536);
	} else {
		return 0;
	}

	if (time(NULL) < time2flash)
		return 0;

	return 1;
}

static int mr500_detect_main(void (*priv)__attribute__((unused)), char *packet_buff, int packet_buff_len)
{
	struct ether_arp *arphdr;
	int ret = 0;

	if (!len_check(packet_buff_len, sizeof(struct ether_arp), "ARP"))
		goto out;

	arphdr = (struct ether_arp *)packet_buff;
	if (arphdr->ea_hdr.ar_op != htons(ARPOP_REQUEST))
		goto out;

	if (*((unsigned int *)arphdr->arp_tpa) != htonl(mr500_ip))
		goto out;

	ret = 1;

out:
	return ret;
}

const struct router_type mr500 = {
	.desc = "MR500 router",
	.detect_pre = NULL,
	.detect_main = mr500_detect_main,
	.detect_post = tftp_client_detect_post,
	.image = &img_uboot,
	.priv_size = sizeof(struct mr500_priv),
};

static int mr600_detect_main(void (*priv)__attribute__((unused)), char *packet_buff, int packet_buff_len)
{
	struct ether_arp *arphdr;
	int ret = 0;

	if (!len_check(packet_buff_len, sizeof(struct ether_arp), "ARP"))
		goto out;

	arphdr = (struct ether_arp *)packet_buff;
	if (arphdr->ea_hdr.ar_op != htons(ARPOP_REQUEST))
		goto out;

	if (*((unsigned int *)arphdr->arp_tpa) != htonl(om2p_ip))
		goto out;

	if (arphdr->arp_tha[0] != 'M')
		goto out;

	if (arphdr->arp_tha[1] != 'R')
		goto out;

	if (arphdr->arp_tha[2] != '6')
		goto out;

	if (arphdr->arp_tha[3] != '0')
		goto out;

	if (arphdr->arp_tha[4] != '0')
		goto out;

	ret = 1;

out:
	return ret;
}

const struct router_type mr600 = {
	.desc = "MR600 router",
	.detect_pre = NULL,
	.detect_main = mr600_detect_main,
	.detect_post = tftp_client_detect_post,
	.image = &img_ce_om2p,
	.priv_size = sizeof(struct om2p_priv),
};

static int om2p_detect_main(void (*priv)__attribute__((unused)), char *packet_buff, int packet_buff_len)
{
	struct ether_arp *arphdr;
	int ret = 0;

	if (!len_check(packet_buff_len, sizeof(struct ether_arp), "ARP"))
		goto out;

	arphdr = (struct ether_arp *)packet_buff;
	if (arphdr->ea_hdr.ar_op != htons(ARPOP_REQUEST))
		goto out;

	if (*((unsigned int *)arphdr->arp_tpa) != htonl(om2p_ip))
		goto out;

	/* target mac address field has to be zero */
	if (arphdr->arp_tha[0] | arphdr->arp_tha[1] | arphdr->arp_tha[2] |
	    arphdr->arp_tha[3] | arphdr->arp_tha[4] | arphdr->arp_tha[5])
		goto out;

	ret = 1;

out:
	return ret;
}

const struct router_type om2p = {
	.desc = "OM2P router",
	.detect_pre = NULL,
	.detect_main = om2p_detect_main,
	.detect_post = tftp_client_detect_post,
	.image = &img_ce_om2p,
	.priv_size = sizeof(struct om2p_priv),
};
