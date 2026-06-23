/* SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: Marek Lindner <marek.lindner@mailbox.org>
 */

#ifndef __AP51_FLASH_ROUTER_TFTP_SERVER_H__
#define __AP51_FLASH_ROUTER_TFTP_SERVER_H__

#include "router_types.h"

struct router_tftp_server {
	struct router_type router_type;
	unsigned int ip;
	uint8_t wait_arp_count;
};

extern const struct router_tftp_server ubnt;

void tftp_server_flash_time_set(struct node *node);
int tftp_server_flash_completed(struct node *node,
				const struct ether_arp *arphdr);

#endif /* __AP51_FLASH_ROUTER_TFTP_SERVER_H__ */
