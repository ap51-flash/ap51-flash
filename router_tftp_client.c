// SPDX-License-Identifier: GPL-3.0-or-later
/* SPDX-FileCopyrightText: Marek Lindner <mareklindner@neomailbox.ch>
 * SPDX-FileCopyrightText: Sven Eckelmann <sven@narfation.org>
 */

#include "router_tftp_client.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include "compat.h"
#include "flash.h"
#include "proto.h"
#include "router_images.h"
#include "router_types.h"

#define MR500_IP 3232260872UL /* 192.168.99.8 */
#define OM2P_IP 3232261128UL /* 192.168.100.8 */
#define ZYXEL_IP 3232235875UL /* 192.168.1.99 */

struct mr500_priv {
	time_t start_flash;
};

struct om2p_priv {
	time_t start_flash;
};

static int tftp_client_detect_main(const struct router_type *router_type,
				   void (*priv)__attribute__((unused)),
				   const char *packet_buff, int packet_buff_len)
{
	const struct mac_accept_entry *mac_accept_entry;
	struct router_tftp_client *tftp_client;
	struct ether_header *eth_hdr;
	struct ether_arp *arphdr;
	uint8_t arp_u8;
	uint8_t mac_u8;
	bool mismatch;
	size_t i;
	size_t j;

	tftp_client = container_of(router_type, struct router_tftp_client,
				   router_type);

	eth_hdr = (struct ether_header *)packet_buff;
	if (eth_hdr->ether_type != htons(ETH_P_ARP))
		return 0;

	if (!len_check(packet_buff_len, ETH_HLEN + sizeof(struct ether_arp), "ARP"))
		return 0;

	arphdr = (struct ether_arp *)(packet_buff + ETH_HLEN);
	if (arphdr->ea_hdr.ar_op != htons(ARPOP_REQUEST))
		return 0;

	if (*((unsigned int *)arphdr->arp_tpa) != htonl(tftp_client->ip))
		return 0;

	if (tftp_client->mac_accept_entries_num == 0)
		return 1;

	for (i = 0; i < tftp_client->mac_accept_entries_num; i++) {
		mac_accept_entry = &tftp_client->mac_accept_entries[i];

		mismatch = false;

		for (j = 0; j < 6; j++) {
			arp_u8 = arphdr->arp_tha[j] & mac_accept_entry->mask[j];
			mac_u8 = mac_accept_entry->mac[j] & mac_accept_entry->mask[j];

			if (arp_u8 != mac_u8) {
				mismatch = true;
				break;
			}
		}

		if (!mismatch)
			return 1;
	}

	return 0;
}

static void tftp_client_detect_post(struct node *node, const char *packet_buff,
				    int packet_buff_len)
{
	struct ether_header *eth_hdr;
	struct ether_arp *arphdr;

	eth_hdr = (struct ether_header *)packet_buff;
	if (eth_hdr->ether_type != htons(ETH_P_ARP))
		goto out;

	if (!len_check(packet_buff_len, ETH_HLEN + sizeof(struct ether_arp), "ARP"))
		goto out;

	arphdr = (struct ether_arp *)(packet_buff + ETH_HLEN);

	node->flash_mode = FLASH_MODE_TFTP_CLIENT;
	node->his_ip_addr = load_ip_addr(arphdr->arp_spa);
	node->our_ip_addr = load_ip_addr(arphdr->arp_tpa);

out:
	return;
}

void tftp_client_flash_time_set(struct node *node)
{
	struct mr500_priv *mr500_priv;
	struct om2p_priv *om2p_priv;

	if (node->router_type == &mr500.router_type) {
		mr500_priv = node->router_priv;
		mr500_priv->start_flash = time(NULL);
	} else if ((node->router_type == &mr600.router_type) ||
		   (node->router_type == &mr900.router_type) ||
		   (node->router_type == &mr1750.router_type) ||
		   (node->router_type == &a40.router_type) ||
		   (node->router_type == &a42.router_type) ||
		   (node->router_type == &a60.router_type) ||
		   (node->router_type == &a62.router_type) ||
		   (node->router_type == &ap440.router_type) ||
		   (node->router_type == &ap840.router_type) ||
		   (node->router_type == &ap840e.router_type) ||
		   (node->router_type == &om2p.router_type) ||
		   (node->router_type == &om5p.router_type) ||
		   (node->router_type == &om5pac.router_type) ||
		   (node->router_type == &om5pan.router_type) ||
		   (node->router_type == &p60.router_type) ||
		   (node->router_type == &d200.router_type) ||
		   (node->router_type == &g200.router_type) ||
		   (node->router_type == &pa300.router_type) ||
		   (node->router_type == &pa1200.router_type) ||
		   (node->router_type == &pa2200.router_type) ||
		   (node->router_type == &pax1800.router_type) ||
		   (node->router_type == &pax1800v2.router_type) ||
		   (node->router_type == &tw420.router_type) ||
		   (node->router_type == &zyxel.router_type)) {

		om2p_priv = node->router_priv;
		om2p_priv->start_flash = time(NULL);
	}
}

int tftp_client_flash_completed(struct node *node)
{
	struct mr500_priv *mr500_priv;
	struct om2p_priv *om2p_priv;
	time_t time2flash;

	if (node->router_type == &mr500.router_type) {
		mr500_priv = node->router_priv;
		time2flash = mr500_priv->start_flash + 45 + (node->image_state.total_bytes_sent / 65536);
	} else if ((node->router_type == &mr600.router_type) ||
		   (node->router_type == &mr900.router_type) ||
		   (node->router_type == &mr1750.router_type) ||
		   (node->router_type == &a40.router_type) ||
		   (node->router_type == &a42.router_type) ||
		   (node->router_type == &a60.router_type) ||
		   (node->router_type == &a62.router_type) ||
		   (node->router_type == &ap440.router_type) ||
		   (node->router_type == &ap840.router_type) ||
		   (node->router_type == &ap840e.router_type) ||
		   (node->router_type == &om2p.router_type) ||
		   (node->router_type == &om5p.router_type) ||
		   (node->router_type == &om5pac.router_type) ||
		   (node->router_type == &om5pan.router_type) ||
		   (node->router_type == &p60.router_type) ||
		   (node->router_type == &d200.router_type) ||
		   (node->router_type == &g200.router_type) ||
		   (node->router_type == &pa300.router_type) ||
		   (node->router_type == &pa1200.router_type) ||
		   (node->router_type == &pa2200.router_type) ||
		   (node->router_type == &pax1800.router_type) ||
		   (node->router_type == &pax1800v2.router_type) ||
		   (node->router_type == &tw420.router_type) ||
		   (node->router_type == &zyxel.router_type)) {

		om2p_priv = node->router_priv;
		time2flash = om2p_priv->start_flash + 10 + (node->image_state.total_bytes_sent / 65536);
	} else {
		return 0;
	}

	if (time(NULL) < time2flash)
		return 0;

	return 1;
}

const struct router_tftp_client mr500 = {
	.router_type = {
		.desc = "MR500 router",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_uboot,
		.priv_size = sizeof(struct mr500_priv),
	},
	.ip = MR500_IP,
};

static const struct mac_accept_entry mr600_mac_accept[] = {
	{
		.mac = {'M', 'R', '6', '0', '0', 0},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0x00},
	},
};

const struct router_tftp_client mr600 = {
	.router_type = {
		.desc = "MR600",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = mr600_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(mr600_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry mr900_mac_accept[] = {
	{
		.mac = {'M', 'R', '9', '0', '0', 0},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0x00},
	},
};

const struct router_tftp_client mr900 = {
	.router_type = {
		.desc = "MR900",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = mr900_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(mr900_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry mr1750_mac_accept[] = {
	{
		.mac = {'M', 'R', '1', '7', '5', '0'},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client mr1750 = {
	.router_type = {
		.desc = "MR1750",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = mr1750_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(mr1750_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry om2p_mac_accept[] = {
	{
		.mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
	{
		.mac = {'O', 'M', '2', 'P', 'V', '4'},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client om2p = {
	.router_type = {
		.desc = "OM2P",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = om2p_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(om2p_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry a40_mac_accept[] = {
	{
		.mac = {'A', '4', '0', 0x00, 0x00, 0x00},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client a40 = {
	.router_type = {
		.desc = "A40",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.image_desc = "A60",
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = a40_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(a40_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry a60_mac_accept[] = {
	{
		.mac = {'A', '6', '0', 0x00, 0x00, 0x00},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client a60 = {
	.router_type = {
		.desc = "A60",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = a60_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(a60_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry a42_mac_accept[] = {
	{
		.mac = {'A', '4', '2', 0x00, 0x00, 0x00},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client a42 = {
	.router_type = {
		.desc = "A42",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = a42_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(a42_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry a62_mac_accept[] = {
	{
		.mac = {'A', '6', '2', 0x00, 0x00, 0x00},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client a62 = {
	.router_type = {
		.desc = "A62",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = a62_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(a62_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry ap840_mac_accept[] = {
	{
		.mac = {0xf8, 0xd9, 0xb8, 0x00, 0x01, 0x01},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client ap840 = {
	.router_type = {
		.desc = "AP840",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = ap840_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(ap840_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry ap440_mac_accept[] = {
	{
		.mac = {0xF8, 0xD9, 0xB8, 0x00, 0x03, 0x01},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client ap440 = {
	.router_type = {
		.desc = "AP440",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = ap440_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(ap440_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry ap840e_mac_accept[] = {
	{
		.mac = {0xf8, 0xd9, 0xb8, 0x00, 0x02, 0x01},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client ap840e = {
	.router_type = {
		.desc = "AP840E",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = ap840e_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(ap840e_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry tw420_mac_accept[] = {
	{
		.mac = {0xF8, 0xD9, 0xB8, 0x00, 0x04, 0x01},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client tw420 = {
	.router_type = {
		.desc = "TW420",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = tw420_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(tw420_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry om5p_mac_accept[] = {
	{
		.mac = {'O', 'M', '5', 'P', 0x00, 0x00},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client om5p = {
	.router_type = {
		.desc = "OM5P",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = om5p_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(om5p_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry om5pan_mac_accept[] = {
	{
		.mac = {'O', 'M', '5', 'P', 'A', 'N'},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client om5pan = {
	.router_type = {
		.desc = "OM5P-AN",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.image_desc = "OM5P",
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = om5pan_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(om5pan_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry om5pac_mac_accept[] = {
	{
		.mac = {'O', 'M', '5', 'P', 'A', 'C'},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client om5pac = {
	.router_type = {
		.desc = "OM5P-AC",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.image_desc = "OM5PAC",
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = om5pac_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(om5pac_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry p60_mac_accept[] = {
	{
		.mac = {'P', '6', '0', 0x00, 0x00, 0x00},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client p60 = {
	.router_type = {
		.desc = "P60",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.image_desc = "P60",
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = p60_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(p60_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry d200_mac_accept[] = {
	{
		.mac = {'D', '2', '0', '0', 0x00, 0x00},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client d200 = {
	.router_type = {
		.desc = "D200",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.image_desc = "D200",
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = d200_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(d200_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry g200_mac_accept[] = {
	{
		.mac = {'G', '2', '0', '0', 0x00, 0x00},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client g200 = {
	.router_type = {
		.desc = "G200",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.image_desc = "G200",
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = g200_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(g200_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry pa300_mac_accept[] = {
	{
		.mac = {'P', 'A', '3', '0', '0', 0x00},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client pa300 = {
	.router_type = {
		.desc = "PA300",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = pa300_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(pa300_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry pa1200_mac_accept[] = {
	{
		.mac = {'R', 'K', '1', '2', '0', '0'},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
	{
		.mac = {'P', 'A', '1', '2', '0', '0'},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client pa1200 = {
	.router_type = {
		.desc = "PA1200",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = pa1200_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(pa1200_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry pa2200_mac_accept[] = {
	{
		.mac = {'R', 'K', '2', '1', '0', '0'},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
	{
		.mac = {'P', 'A', '2', '2', '0', '0'},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client pa2200 = {
	.router_type = {
		.desc = "PA2200",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = pa2200_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(pa2200_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry pax1800_mac_accept[] = {
	{
		.mac = {'P', 'A', 'X', '1', '8', '0'},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client pax1800 = {
	.router_type = {
		.desc = "PAX1800",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = pax1800_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(pax1800_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry pax1800v2_mac_accept[] = {
	{
		.mac = {'P', 'A', 'X', '1', '8', '2'},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client pax1800v2 = {
	.router_type = {
		.desc = "PAX1800v2",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_ce,
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = pax1800v2_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(pax1800v2_mac_accept),
	.ip = OM2P_IP,
};

static const struct mac_accept_entry zyxel_mac_accept[] = {
	{
		.mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		.mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
};

const struct router_tftp_client zyxel = {
	.router_type = {
		.desc = "Zyxel",
		.detect_pre = NULL,
		.detect_main = tftp_client_detect_main,
		.detect_post = tftp_client_detect_post,
		.image = &img_zyxel,
		.image_desc = "Zyxel",
		.priv_size = sizeof(struct om2p_priv),
	},
	.mac_accept_entries = zyxel_mac_accept,
	.mac_accept_entries_num = ARRAY_SIZE(zyxel_mac_accept),
	.ip = ZYXEL_IP,
};
