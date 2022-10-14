// SPDX-License-Identifier: GPL-3.0-or-later
/* SPDX-FileCopyrightText: Marek Lindner <mareklindner@neomailbox.ch>
 */

#include "router_netboot_server.h"

#include <stdint.h>

#include "compat.h"
#include "flash.h"
#include "proto.h"
#include "router_images.h"

#define NETBOOT_SERVER_IP 3232255489UL /* 192.168.78.1 */
#define NETBOOT_RANGE_MIN 3232255490UL /* 192.168.78.2 */
#define NETBOOT_RANGE_MAX 3232255742UL /* 192.168.78.254 */

enum netboot_client_state{
    DHCP_STATE_UNKNOWN,
    DHCP_STATE_DISCOVER,
    DHCP_STATE_OFFER,
    DHCP_STATE_REQUEST,
    DHCP_STATE_ACK,
};

struct netboot_server_priv {
	enum netboot_client_state netboot_state;
};

static int netboot_server_detect_main(const struct router_type *router_type,
				      void (*priv)__attribute__((unused)),
				      const char *packet_buff, int packet_buff_len)
{
	// struct netboot_server_priv *server_priv = priv;
	struct router_netboot_server *netboot_server;
	struct ether_header *eth_hdr;
	bool oui_found = false;
	struct oui_entry *oui;
	struct udphdr *udphdr;
	struct iphdr *iphdr;
	size_t iphdr_len;
	size_t idx;

	netboot_server = container_of(router_type, struct router_netboot_server,
				      router_type);

	eth_hdr = (struct ether_header *)packet_buff;

	if (netboot_server->oui_entries_num > 0) {
		for (idx = 0; idx < netboot_server->oui_entries_num; idx++) {
			oui = &netboot_server->oui_entries[idx];

			if (eth_hdr->ether_shost[0] != oui->mac[0] ||
			    eth_hdr->ether_shost[1] != oui->mac[1] ||
			    eth_hdr->ether_shost[2] != oui->mac[2])
				continue;

			oui_found = true;
			break;
		}

		if (!oui_found)
			return 0;
	}

	if (eth_hdr->ether_type != htons(ETH_P_IP))
		goto err;

	packet_buff += ETH_HLEN;
	packet_buff_len -= ETH_HLEN;

	if (!len_check(packet_buff_len, sizeof(struct iphdr), "IPv4"))
		goto err;

	iphdr = (struct iphdr *)packet_buff;
	if (iphdr->ihl < 5)
		goto err;

	iphdr_len = iphdr->ihl * 4;
	if (!len_check(packet_buff_len, iphdr_len, "IPv4 full"))
		goto err;

	if (iphdr->protocol != IPPROTO_UDP)
		goto err;

	packet_buff += iphdr_len;
	packet_buff_len -= iphdr_len;

	if (!len_check(packet_buff_len, sizeof(struct udphdr), "UDP"))
		goto err;

	udphdr = (struct udphdr *)packet_buff;

	if (udphdr->dest != htons(IPPORT_BOOTP_SERVER) ||
	    udphdr->source != htons(IPPORT_BOOTP_CLIENT))
		goto err;

	return 1;

err:
	fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: is of type '%s' but not in recovery mode\n",
		eth_hdr->ether_shost[0], eth_hdr->ether_shost[1],
		eth_hdr->ether_shost[2], eth_hdr->ether_shost[3],
		eth_hdr->ether_shost[4], eth_hdr->ether_shost[5],
		router_type->desc);
	return 0;
}

static void netboot_server_detect_post(struct node *node,
				       const char (*packet_buff)__attribute__((unused)),
				       int (packet_buff_len)__attribute__((unused)))
{
	struct router_netboot_server *netboot_server;
	unsigned int bootp_num_ip_addrs;
	unsigned bootp_ip_addr_offset;

	netboot_server = container_of(node->router_type, struct router_netboot_server,
				      router_type);

	bootp_num_ip_addrs = netboot_server->bootp.range_max - netboot_server->bootp.range_min;
	bootp_ip_addr_offset = node->index % bootp_num_ip_addrs;

	node->flash_mode = FLASH_MODE_NETBOOT_SERVER;
	node->his_ip_addr = netboot_server->bootp.range_min + bootp_ip_addr_offset;
	node->our_ip_addr = netboot_server->bootp.server_ip;
}

static struct oui_entry mikrotik_oui_entries[] = {
	{ .mac = {0x00, 0x0C, 0x42} },
	{ .mac = {0x08, 0x55, 0x31} },
	{ .mac = {0x18, 0xFD, 0x74} },
	{ .mac = {0x2C, 0xC8, 0x1B} },
	{ .mac = {0x48, 0x8F, 0x5A} },
	{ .mac = {0x4C, 0x5E, 0x0C} },
	{ .mac = {0x64, 0xD1, 0x54} },
	{ .mac = {0x6C, 0x3B, 0x6B} },
	{ .mac = {0x74, 0x4D, 0x28} },
	{ .mac = {0xB8, 0x69, 0xF4} },
	{ .mac = {0xC4, 0xAD, 0x34} },
	{ .mac = {0xCC, 0x2D, 0xE0} },
	{ .mac = {0xDC, 0x2C, 0x6E} },
	{ .mac = {0xE4, 0x8D, 0x8C} },
};

const struct router_netboot_server mikrotik = {
	.router_type = {
		.desc = "mikrotik",
		.detect_pre = NULL,
		.detect_main = netboot_server_detect_main,
		.detect_post = netboot_server_detect_post,
		.image = &img_ubnt, // TODO: needs mikrotik/initramfs image check
		.image_desc = "mikrotik",
		.priv_size = sizeof(struct netboot_server_priv),
	},
	.bootp = {
		.server_ip = NETBOOT_SERVER_IP,
		.range_min = NETBOOT_RANGE_MIN,
		.range_max = NETBOOT_RANGE_MAX,
	},
	.oui_entries = mikrotik_oui_entries,
	.oui_entries_num = ARRAY_SIZE(mikrotik_oui_entries),
};
