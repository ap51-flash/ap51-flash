/* SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2009-2019, Marek Lindner <mareklindner@neomailbox.ch>
 */

#ifndef __AP51_FLASH_ROUTER_REDBOOT_H__
#define __AP51_FLASH_ROUTER_REDBOOT_H__

struct node;

struct redboot_type {
	unsigned long flash_size;
	unsigned long freememlo;
	unsigned long flash_addr;
	unsigned long kernel_load_addr;
	int (*detect)(struct node *node);
};

extern const struct router_type redboot;

void redboot_main(struct node *node, const char *telnet_msg);

#endif /* __AP51_FLASH_ROUTER_REDBOOT_H__ */
