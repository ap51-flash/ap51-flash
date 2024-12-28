// SPDX-License-Identifier: GPL-3.0-or-later
/* SPDX-FileCopyrightText: Marek Lindner <marek.lindner@mailbox.org>
 */

#include "router_tftp_server.h"

#include <stdint.h>

#include "compat.h"
#include "flash.h"
#include "proto.h"
#include "router_images.h"

#define UBNT_IP 3232235796UL /* 192.168.1.20 */

static const unsigned int my_ip = 3232235801UL;  /* 192.168.1.25 */

struct tftp_server_priv {
	int arp_count;
};

static void tftp_server_detect_pre(const struct router_type *router_type,
				   const uint8_t *our_mac)
{
	uint8_t bcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	struct router_tftp_server *tftp_server;

	tftp_server = container_of(router_type, struct router_tftp_server,
				   router_type);

	arp_req_send(our_mac, bcast_mac, htonl(my_ip), htonl(tftp_server->ip));
}

static int tftp_server_detect_main(const struct router_type *router_type,
				   void *priv, const char *packet_buff,
				   int packet_buff_len)
{
	struct tftp_server_priv *server_priv = priv;
	struct router_tftp_server *tftp_server;
	struct ether_arp *arphdr;
	int ret = 0;

	tftp_server = container_of(router_type, struct router_tftp_server,
				   router_type);

	if (!len_check(packet_buff_len, sizeof(struct ether_arp), "ARP"))
		goto out;

	arphdr = (struct ether_arp *)packet_buff;
	if (arphdr->ea_hdr.ar_op != htons(ARPOP_REPLY))
		goto out;

	if (load_ip_addr(arphdr->arp_spa) != htonl(tftp_server->ip))
		goto out;

	if (server_priv->arp_count < tftp_server->wait_arp_count) {
		server_priv->arp_count++;
		goto out;
	}

	ret = 1;

out:
	return ret;
}

static void tftp_server_detect_post(struct node *node, const char *packet_buff,
				    int packet_buff_len)
{
	struct ether_arp *arphdr;

	if (!len_check(packet_buff_len, sizeof(struct ether_arp), "ARP"))
		goto out;

	arphdr = (struct ether_arp *)packet_buff;

	node->flash_mode = FLASH_MODE_TFTP_SERVER;
	node->his_ip_addr = load_ip_addr(arphdr->arp_spa);
	node->our_ip_addr = load_ip_addr(arphdr->arp_tpa);

out:
	return;
}

const struct router_tftp_server ubnt = {
	.router_type = {
		.desc = "ubiquiti",
		.detect_pre = tftp_server_detect_pre,
		.detect_main = tftp_server_detect_main,
		.detect_post = tftp_server_detect_post,
		.image = &img_ubnt,
		.image_desc = "ubiquiti",
		.priv_size = sizeof(struct tftp_server_priv),
	},
	.ip = UBNT_IP,
	.wait_arp_count = 20,
};
