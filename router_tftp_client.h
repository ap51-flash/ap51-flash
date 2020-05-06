/* SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2009-2019, Marek Lindner <mareklindner@neomailbox.ch>
 */

#ifndef __AP51_FLASH_ROUTER_TFTP_CLIENT_H__
#define __AP51_FLASH_ROUTER_TFTP_CLIENT_H__

#include "router_types.h"

struct node;

struct mac_accept_entry {
	uint8_t mac[6];
	uint8_t mask[6];
};

struct router_tftp_client {
	struct router_type router_type;
	const struct mac_accept_entry *mac_accept_entries;
	size_t mac_accept_entries_num;
	unsigned int ip;
};

extern const struct router_tftp_client a40;
extern const struct router_tftp_client a42;
extern const struct router_tftp_client a60;
extern const struct router_tftp_client a62;
extern const struct router_tftp_client ap840;
extern const struct router_tftp_client d200;
extern const struct router_tftp_client g200;
extern const struct router_tftp_client mr1750;
extern const struct router_tftp_client mr500;
extern const struct router_tftp_client mr600;
extern const struct router_tftp_client mr900;
extern const struct router_tftp_client om2p;
extern const struct router_tftp_client om5p;
extern const struct router_tftp_client om5pac;
extern const struct router_tftp_client om5pan;
extern const struct router_tftp_client p60;
extern const struct router_tftp_client pa300;
extern const struct router_tftp_client pa1200;
extern const struct router_tftp_client pa2200;
extern const struct router_tftp_client zyxel;

void tftp_client_flash_time_set(struct node *node);
int tftp_client_flash_completed(struct node *node);

#endif /* __AP51_FLASH_ROUTER_TFTP_CLIENT_H__ */
