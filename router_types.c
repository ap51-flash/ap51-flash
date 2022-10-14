// SPDX-License-Identifier: GPL-3.0-or-later
/* SPDX-FileCopyrightText: Marek Lindner <mareklindner@neomailbox.ch>
 */

#include "router_types.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "compat.h"
#include "flash.h"
#include "list.h"
#include "router_images.h"
#include "router_redboot.h"
#include "router_tftp_client.h"
#include "router_tftp_server.h"
#include "router_netconsole.h"
#include "router_netboot_server.h"

#if defined(CLEAR_SCREEN)
#if defined(LINUX) || defined(WIN32)
#include <stdlib.h>
#endif
#endif

int router_types_priv_size = 0;
static DECLARE_LIST_HEAD(mac_allowlist);

static const struct router_type *router_types[] = {
	&a40.router_type,
	&a42.router_type,
	&a60.router_type,
	&a62.router_type,
	&ap440.router_type,
	&ap840.router_type,
	&ap840e.router_type,
	&d200.router_type,
	&g200.router_type,
	&mr1750.router_type,
	&mr500.router_type,
	&mr600.router_type,
	&mr900.router_type,
	&om2p.router_type,
	&om5p.router_type,
	&om5pac.router_type,
	&om5pan.router_type,
	&p60.router_type,
	&redboot,
	&tw420.router_type,
	&ubnt.router_type,
	&zyxel.router_type,
	&ap121f,
	&pa300.router_type,
	&pa1200.router_type,
	&pa2200.router_type,
	&pax1800.router_type,
	&pax1800v2.router_type,
	&mikrotik.router_type,
	NULL,
};

static int read_mac(uint8_t mac[ETH_ALEN], const char *macstr)
{
	int ret;

	ret = sscanf(macstr, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
		     &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	if (ret != 6)
		ret = sscanf(macstr, "%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX",
			     &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

	return (ret == 6);
}

int mac_allowlist_add(const char *macstr)
{
	uint8_t mac[ETH_ALEN];
	struct mac_allowlist_entry *new_entry;

	if (!read_mac(mac, macstr)) {
		fprintf(stderr, "Error - could not add MAC address to allowlist: %s\n", macstr);
		return -EINVAL;
	}

	new_entry = malloc(sizeof(*new_entry));
	if (!new_entry) {
		fprintf(stderr, "Error - could not allocate memory for new MAC allowlist entry\n");
		return -ENOMEM;
	}

	memcpy(new_entry->mac, mac, ETH_ALEN);
	list_add(&new_entry->list, &mac_allowlist);

	return 0;
}

static bool mac_allowlist_find(const uint8_t *mac)
{
	struct mac_allowlist_entry *current;

	list_for_each_entry(current, &mac_allowlist, list) {
		if (memcmp(mac, current->mac, ETH_ALEN) == 0)
			return true;
	}

	return false;
}

int router_types_init(void)
{
	int ret = -1;
	const struct router_type **router_type;

	for (router_type = router_types; *router_type; ++router_type) {
		if (!(*router_type)->image) {
			fprintf(stderr,
				"Error - can't have router definition without image attribute set: %s\n",
				(*router_type)->desc);
			goto out;
		}

		router_types_priv_size += (*router_type)->priv_size;
	}

	ret = 0;

out:
	return ret;
}

void router_types_detect_pre(const uint8_t *our_mac)
{
	const struct router_type **router_type;

	for (router_type = router_types; *router_type; ++router_type) {
		if (!(*router_type)->detect_pre)
			continue;

		(*router_type)->detect_pre(*router_type, our_mac);
	}
}

int router_types_detect_main(struct node *node, const char *packet_buff,
			     int packet_buff_len)
{
	const struct router_type **router_type;
	struct router_info *router_info;
	void *priv = node + 1;
	int ret = 0;

	for (router_type = router_types; *router_type; ++router_type) {
		if (!(*router_type)->detect_main)
			goto next;

		ret = (*router_type)->detect_main(*router_type,
						  priv, packet_buff,
						  packet_buff_len);
		if (ret != 1)
			goto next;

		/* we detected a router that we have no image for */
		if ((*router_type)->image->file_size < 1) {
			fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: is of type '%s' that we have no image for\n",
				node->his_mac_addr[0], node->his_mac_addr[1],
				node->his_mac_addr[2], node->his_mac_addr[3],
				node->his_mac_addr[4], node->his_mac_addr[5],
				(*router_type)->desc);

			node->status = NODE_STATUS_NO_FLASH;
			ret = 0;
			break;
		}

		/* we detected a router whose MAC is not allowlisted */
		if (!list_empty(&mac_allowlist) && !mac_allowlist_find(node->his_mac_addr)) {
			fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: is of type '%s' but MAC does not match MAC filter\n",
				node->his_mac_addr[0], node->his_mac_addr[1],
				node->his_mac_addr[2], node->his_mac_addr[3],
				node->his_mac_addr[4], node->his_mac_addr[5],
				(*router_type)->desc);

			node->status = NODE_STATUS_NO_FLASH;
			ret = 0;
			break;
		}

		if ((*router_type)->image->type == IMAGE_TYPE_CE) {
			router_info = router_image_router_get((*router_type)->image,
							      (*router_type)->image_desc ? (char *)(*router_type)->image_desc : (char *)(*router_type)->desc);
			if (!router_info) {
				fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: is of type '%s' that we have no image for (ce)\n",
					node->his_mac_addr[0],
					node->his_mac_addr[1],
					node->his_mac_addr[2],
					node->his_mac_addr[3],
					node->his_mac_addr[4],
					node->his_mac_addr[5],
					(*router_type)->desc);

				node->status = NODE_STATUS_NO_FLASH;
				ret = 0;
				break;
			}
		}

		our_mac_set(node);
		node->router_type = (struct router_type *)(*router_type);
		node->router_priv = priv;

#if defined(CLEAR_SCREEN)
#if defined(LINUX)
		if (num_nodes_flashed > 0)
			ret = system("clear");
#elif defined(WIN32)
		if (num_nodes_flashed > 0)
			ret = system("cls");
#else
#error CLEAR_SCREEN is not supported on your OS
#endif
		/* keep gcc happy by retrieving the return value of the system() call */
		ret = 1;
#endif

		fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: device type '%s' detected\n",
			node->his_mac_addr[0], node->his_mac_addr[1],
			node->his_mac_addr[2], node->his_mac_addr[3],
			node->his_mac_addr[4], node->his_mac_addr[5],
			node->router_type->desc);

		if (!(*router_type)->detect_post)
			break;

		(*router_type)->detect_post(node, packet_buff, packet_buff_len);
		break;

next:
		priv = (char *)priv + (*router_type)->priv_size;
	}

	return ret;
}
