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
 *
 * SPDX-License-Identifier: GPL-3.0+
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
