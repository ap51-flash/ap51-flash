// SPDX-License-Identifier: GPL-3.0-or-later
/* SPDX-FileCopyrightText: Marek Lindner <mareklindner@neomailbox.ch>
 */

#include "flash.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "list.h"
#include "proto.h"
#include "router_tftp_client.h"
#include "router_types.h"
#include "socket.h"

static int running = 1;
static unsigned int seen_node_count = 0;
static DECLARE_LIST_HEAD(node_list);
static uint8_t our_mac[] = {0x00, 0xba, 0xbe, 0xca, 0xff, 0x00};

#if defined(CLEAR_SCREEN)
int num_nodes_flashed = 0;
#endif

#define PACKET_BUFF_LEN 2000
#define READ_SLEEP_SEC 0
#define READ_SLEEP_USEC 250000

struct node *node_list_get(const uint8_t *mac_addr)
{
	struct node *node;

	list_for_each_entry(node, &node_list, list) {
		if (memcmp(node->his_mac_addr, mac_addr, ETH_ALEN) != 0)
			continue;

		return node;
	}

	node = malloc(sizeof(struct node) + router_types_priv_size);
	if (!node)
		return NULL;

	seen_node_count++;

	memset(node, 0, sizeof(struct node) + router_types_priv_size);
	memcpy(node->his_mac_addr, mac_addr, ETH_ALEN);
	node->index = seen_node_count;
	node->image_state.fd = -1;
	list_add(&node->list, &node_list);

	return node;
}

static void node_list_free(void)
{
	struct node *node, *node_s;

	list_for_each_entry_safe(node, node_s, &node_list, list) {
		list_del(&node->list);
		free(node);
	}
}

static void node_list_maintain(void)
{
	struct node *node, *node_s;
	int ret;

	list_for_each_entry_safe(node, node_s, &node_list, list) {
		switch (node->status) {
		case NODE_STATUS_UNKNOWN:
		case NODE_STATUS_RESET_SENT:
		case NODE_STATUS_DETECTING:
			/* ignored */
			break;
		case NODE_STATUS_DETECTED:
			switch (node->flash_mode) {
			case FLASH_MODE_TFTP_SERVER:
				tftp_init_upload(node);
				break;
			case FLASH_MODE_REDBOOT:
				telnet_handle_connection(node);
				break;
			case FLASH_MODE_TFTP_CLIENT:
			case FLASH_MODE_NETCONSOLE:
			case FLASH_MODE_NETBOOT_SERVER:
				/* ignored; handled in handle_udp_packet */
				break;
			case FLASH_MODE_UKNOWN:
				fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: Error, flash mode unknown.\n",
					node->his_mac_addr[0], node->his_mac_addr[1],
					node->his_mac_addr[2], node->his_mac_addr[3],
					node->his_mac_addr[4], node->his_mac_addr[5]);
				break;
			}
			break;
		case NODE_STATUS_FLASHING:
			/* if (node->flash_mode == FLASH_MODE_REDBOOT)
				telnet_keep_alive(node); */
			break;
		case NODE_STATUS_FINISHED:
			if (node->flash_mode != FLASH_MODE_TFTP_CLIENT)
				break;

			ret = tftp_client_flash_completed(node);
			if (ret == 0)
				break;

			fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s: flash complete. Device ready to unplug.\n",
				node->his_mac_addr[0], node->his_mac_addr[1],
				node->his_mac_addr[2], node->his_mac_addr[3],
				node->his_mac_addr[4], node->his_mac_addr[5],
				node->router_type->desc);
			node->status = NODE_STATUS_REBOOTED;
#if defined(CLEAR_SCREEN)
			num_nodes_flashed++;
#endif
			break;
		case NODE_STATUS_REBOOTED:
		case NODE_STATUS_NO_FLASH:
			/* check timeout and call _node_list_free(list); */
			break;
		}
	}
}

void our_mac_set(struct node *node)
{
	memcpy(node->our_mac_addr, our_mac, ETH_ALEN);

	/* TODO: 256 addresses might not be sufficient */
	our_mac[5]++;
}

static void sig_handler(int signal)
{
	switch (signal) {
	case SIGINT:
	case SIGTERM:
		running = 0;
		break;
	}
}

int flash_start(const char *iface)
{
	char *packet_buff_align;
	char *packet_buff;
	int ret, sleep_sec, sleep_usec;

	ret = socket_open(iface);
	if (ret < 0)
		goto out;

	packet_buff_align = malloc(PACKET_BUFF_LEN + NET_IP_ALIGN);
	if (!packet_buff_align)
		goto list_free;

	packet_buff = &packet_buff_align[NET_IP_ALIGN];

	ret = proto_init();
	if (ret < 0)
		goto pack_free;

	ret = router_types_init();
	if (ret < 0)
		goto proto_free;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	sleep_sec = READ_SLEEP_SEC;
	sleep_usec = READ_SLEEP_USEC;

	while (running) {
		ret = socket_read(packet_buff, PACKET_BUFF_LEN, &sleep_sec,
				  &sleep_usec);

		if (ret == 0) {
			router_types_detect_pre(our_mac);
			node_list_maintain();
		}

		if (ret <= 0)
			goto reset_sleep;

		handle_eth_packet(packet_buff, ret);
		continue;

reset_sleep:
		sleep_sec = READ_SLEEP_SEC;
		sleep_usec = READ_SLEEP_USEC;
	}

	ret = 0;

proto_free:
	proto_free();
pack_free:
	free(packet_buff_align);
list_free:
	node_list_free();
	socket_close(iface);
out:
	return ret;
}
