/*
 * Copyright (C) Sven-Ola, Open Mesh, Inc., Marek Lindner
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

#include <pcap.h>
#include "uipopt.h"
#include "psock.h"

#ifdef WIN32
/* WIN32 */
#include <windows.h>
#include "ap51-flash-res.h"
#include "missing-win32.h"
#define PCAP_TIMEOUT_MS 1000
#elif defined(OSX)
/* OSX */
#define O_BINARY 0
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include "missing-osx.h"
#undef HTONS
#define PCAP_TIMEOUT_MS 200
#elif defined(LINUX)
/* Linux */
#define O_BINARY 0
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#define PCAP_TIMEOUT_MS 200
#else
#error Unsupported PLATFORM
#endif

typedef struct ap51_flash_state {
	struct psock p;
	char inputbuffer[4096];
} uip_tcp_appstate_t;

struct device_info {
	unsigned long full_size;
	unsigned long freememlo;
	unsigned long flash_size;
	unsigned long flash_addr;
	unsigned kernel_part_size;
	unsigned long kernel_load_addr;
	int options;
};

struct flash_from_file {
	int fd;
	int file_size;
	int flash_size;
	char *fname;
	char buff[2];
};

/* flash modes */
enum {
	MODE_NONE,
	MODE_REDBOOT,
	MODE_MAYBE_REDBOOT,
	MODE_TFTP_CLIENT,
};

/* flash from file data */
enum {
	FFF_ROOTFS = 0,
	FFF_KERNEL,
	FFF_UBNT,
	FFF_NUM,
};

#define FREEMEMLO 0x01
#define ROOTFS_RESIZE 0x02
#define SET_FLASH_ADDR 0x04

#define FLASH_PAGE_SIZE 0x10000

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

int ap51_flash(char* device, char* rootfs_filename, char* kernel_filename, int nvram, int uncomp, int special);
void ap51_flash_appcall(void);
void handle_uip_tcp(const unsigned char *packet_buff, unsigned int packet_len);
void handle_uip_conns(void);

extern pcap_t *pcap_fp;
extern unsigned int remote_ip;
extern unsigned int local_ip;
extern unsigned char *tftp_xfer_buff;
extern unsigned long tftp_xfer_size;
extern unsigned char *rootfs_buf;
extern unsigned char *kernel_buf;
extern int rootfs_size;
extern int kernel_size;
extern char flash_mode;
extern int flash_from_file;
extern struct flash_from_file fff_data[];

#endif /* __ap51_FLASH_H__ */
