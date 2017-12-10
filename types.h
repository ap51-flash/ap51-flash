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
 * License-Filename: LICENSES/preferred/GPL-3.0
 */

#ifndef __AP51_FLASH_TYPES_H__
#define __AP51_FLASH_TYPES_H__

#include <stdint.h>

enum node_status {
	NODE_STATUS_UNKNOWN,
	NODE_STATUS_DETECTING,
	NODE_STATUS_DETECTED,
	NODE_STATUS_FLASHING,
	NODE_STATUS_FINISHED,
	NODE_STATUS_RESET_SENT,
	NODE_STATUS_REBOOTED,
	NODE_STATUS_NO_FLASH,
};

enum tcp_status {
	TCP_STATUS_SYN_SENT,
	TCP_STATUS_ESTABLISHED,
	TCP_STATUS_TELNET_READY,
};

enum flash_mode {
	FLASH_MODE_UKNOWN,
	FLASH_MODE_REDBOOT,
	FLASH_MODE_TFTP_SERVER,
	FLASH_MODE_TFTP_CLIENT,
};

enum image_type {
	IMAGE_TYPE_UNKNOWN,
	IMAGE_TYPE_UBOOT,
	IMAGE_TYPE_UBNT,
	IMAGE_TYPE_CI,
	IMAGE_TYPE_CE,
	IMAGE_TYPE_ZYXEL,
};

#define DESC_MAX_LENGTH	30
#define FILE_NAME_MAX_LENGTH 33
#define FLASH_PAGE_SIZE 0x10000

struct list {
	struct list *next;
	void *data;
};

struct image_state {
	int fd;
	unsigned int bytes_sent;
	unsigned int file_size;
	unsigned int total_bytes_sent;
	unsigned int flash_size;
	unsigned int offset;
	unsigned short last_packet_size;
	unsigned short block_acked;
	unsigned short block_sent;
	/* flags */
	unsigned char count_globally:1;
};

struct tcp_state {
	char *packet_buff;
	enum tcp_status status;
	unsigned int his_seq;
	unsigned int his_ack_seq;
	unsigned int his_last_len;
	unsigned int my_seq;
	unsigned int my_ack_seq;
};

struct node {
	uint8_t his_mac_addr[6];
	uint8_t our_mac_addr[6];
	uint32_t his_ip_addr;
	uint32_t our_ip_addr;
	enum node_status status;
	enum flash_mode flash_mode;
	struct router_type *router_type;
	struct image_state image_state;
	struct tcp_state tcp_state;
	void *router_priv;
	/* priv declarations are added at runtime */
};

/**
 * each router type has to declare a router_type struct
 * and add a pointer to the router_types array
 *
 * detect_pre: called by the scheduler in regular intervals
 *             can be used to send ARP requests
 * detect_main: called when an ARP packet is received
 *              return 1 if the router has been detected
 * detect_post: called to let the router_type configure
 *              the node#s settings (e.g. IP)
 */
struct router_type {
	char desc[DESC_MAX_LENGTH];
	void (*detect_pre)(const uint8_t *our_mac);
	int (*detect_main)(void *priv, const char *packet_buff,
			   int packet_buff_len);
	void (*detect_post)(struct node *node, const char *packet_buff,
			    int packet_buff_len);
	struct router_image *image;
	char *image_desc;
	int priv_size;
};

struct file_info {
	char file_name[FILE_NAME_MAX_LENGTH];
	unsigned int file_offset;
	unsigned int file_size;
	unsigned int file_fsize;
};

struct router_info {
	char router_name[DESC_MAX_LENGTH];
	unsigned int file_size;
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

struct redboot_type {
	unsigned long flash_size;
	unsigned long freememlo;
	unsigned long flash_addr;
	unsigned long kernel_load_addr;
	int (*detect)(struct node *node);
};

#endif /* __AP51_FLASH_TYPES_H__ */
