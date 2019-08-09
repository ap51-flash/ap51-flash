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

#ifndef __AP51_FLASH_ROUTER_IMAGES_H__
#define __AP51_FLASH_ROUTER_IMAGES_H__

#include <stdbool.h>

#include "ap51-flash.h"

struct node;
struct router_type;

enum image_type {
	IMAGE_TYPE_UNKNOWN,
	IMAGE_TYPE_UBOOT,
	IMAGE_TYPE_UBNT,
	IMAGE_TYPE_CI,
	IMAGE_TYPE_CE,
	IMAGE_TYPE_ZYXEL,
};

struct router_image {
	enum image_type type;
	char desc[DESC_MAX_LENGTH];
	int (*image_verify)(struct router_image *router_image, const char *buff,
			    unsigned int buff_len, int size);
	const char *path;
	char *embedded_img;
#if defined(LINUX)
	char *embedded_img_pre_check;
	unsigned int embedded_file_size;
#elif defined(OSX)
	char *embedded_img_pre_check;
	unsigned long embedded_file_size;
#elif defined(WIN32)
	unsigned int embedded_img_res;
#endif
	unsigned int file_size;
	struct list *file_list;
	struct list *router_list;
};

struct router_info {
	char router_name[DESC_MAX_LENGTH];
	unsigned int file_size;
};

struct file_info {
	char file_name[FILE_NAME_MAX_LENGTH];
	unsigned int file_offset;
	unsigned int file_size;
	unsigned int file_fsize;
};

struct router_info *router_image_router_get(struct router_image *router_image,
					    const char *router_desc);
struct file_info *router_image_get_file(struct router_type *router_type,
					const char *file_name);
void router_images_init(void);
void router_images_init_embedded(void);
bool router_images_available(void);
void router_images_print_desc(void);
int router_images_verify_path(const char *image_path);
int router_images_open_path(struct node *node);
int router_images_read_data(char *dst, struct node *node);
void router_images_close_path(struct node *node);
unsigned int router_image_get_size(struct router_type *router_type);
struct file_info *router_image_get_file_info(struct router_image *router_image,
					     const char *file_name);

extern struct router_image img_uboot;
extern struct router_image img_ubnt;
extern struct router_image img_ci;
extern struct router_image img_ce;
extern struct router_image img_zyxel;

#endif /* __AP51_FLASH_ROUTER_IMAGES_H__ */
