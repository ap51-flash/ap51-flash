/*
 * Copyright (C) Sven-Ola, open-mesh inc
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

#ifndef __ap51_FLASH_H__
#define __ap51_FLASH_H__

#include "uipopt.h"
#include "psock.h"

typedef struct ap51_flash_state {
	struct psock p;
	struct uip_udp_conn *tftpconn;
	char inputbuffer[4096];
} uip_tcp_appstate_t;

void ap51_flash_appcall(void);

struct device_info {
	unsigned long full_size;
	unsigned long freememlo;
	unsigned long flash_size;
	unsigned long flash_addr;
	unsigned kernel_part_size;
	unsigned long kernel_load_addr;
	int options;
};

#define FREEMEMLO 0x01
#define ROOTFS_RESIZE 0x02
#define SET_FLASH_ADDR 0x04

#ifndef UIP_APPCALL
#define UIP_APPCALL ap51_flash_appcall
#endif /* UIP_APPCALL */

#ifndef REVISION_VERSION
#define REVISION_VERSION_STR "version information not available"
#else
#define REVISION_VERSION_STR REVISION_VERSION
#endif

#ifndef EMBEDDED_DESC
#define EMBEDDED_DESC_STR "no description of embedded files available"
#else
#define EMBEDDED_DESC_STR EMBEDDED_DESC
#endif

typedef int uip_udp_appstate_t;
void ap51_flash_tftp_appcall(void);
#define UIP_UDP_APPCALL ap51_flash_tftp_appcall

int ap51_flash(char* device, char* rootfs_filename, char* kernel_filename, int nvram, int uncomp, int special);
extern void (*gui_output_funcptr)(const char* str);

#endif /* __ap51_FLASH_H__ */
