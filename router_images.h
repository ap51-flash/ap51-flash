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
 */

struct router_info *router_image_router_get(struct router_image *router_image,
					    char *router_desc);
struct file_info *router_image_get_file(struct router_type *router_type,
					char *file_name);
void router_images_init(void);
void router_images_print_desc(void);
int router_images_verify_path(char *image_path);
int router_images_open_path(struct node *node);
int router_images_read_data(char *dst, struct node *node);
void router_images_close_path(struct node *node);

extern struct router_image img_uboot;
extern struct router_image img_ubnt;
extern struct router_image img_ci;
extern struct router_image img_ce;
