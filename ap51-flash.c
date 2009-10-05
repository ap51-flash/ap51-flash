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

#ifdef _DEBUG
#define DEBUG_ALL
#endif

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#include "uip.h"
#include "uip_arp.h"
#include "timer.h"
#include "ap51-flash.h"
#include "device-info.h"
#include "packet.h"

static unsigned char* tftp_buf = 0;
static unsigned char* kernel_buf = 0;
unsigned char *rootfs_buf = 0;

static unsigned long tftp_send = 0;
static unsigned long tftp_size = 0;
static int kernel_size = 0;
int rootfs_size = 0;

static int uncomp_loader = 0;
static int nvram_part_size = 0x00000000;
static int rootfs_part_size = 0x00000000;

static int flash_mode = REDBOOT;
unsigned int tftp_remote_ip = 3232235796UL; /* 192.168.1.20 */
unsigned int tftp_local_ip = 3232235801UL; /* 192.168.1.25 */

#if defined(EMBEDDED_DATA) && !defined(WIN32)
extern unsigned long _binary_openwrt_atheros_vmlinux_lzma_start;
extern unsigned long _binary_openwrt_atheros_vmlinux_lzma_end;
extern unsigned long _binary_openwrt_atheros_vmlinux_lzma_size;

extern unsigned long _binary_openwrt_atheros_root_squashfs_start;
extern unsigned long _binary_openwrt_atheros_root_squashfs_end;
extern unsigned long _binary_openwrt_atheros_root_squashfs_size;

extern unsigned long _binary_openwrt_atheros_ubnt2_squashfs_bin_start;
extern unsigned long _binary_openwrt_atheros_ubnt2_squashfs_bin_end;
extern unsigned long _binary_openwrt_atheros_ubnt2_squashfs_bin_size;
#endif

#ifdef WIN32_GUI

void (*gui_output_funcptr)(const char* str) = 0;
static int gui_output_index = 0;
static char gui_output_buffer[1024];

int gui_printf(const char* format, ...)
{
	va_list ap;
	va_start(ap, format);
	vsprintf(gui_output_buffer + gui_output_index, format, ap);
	{
		char *p = gui_output_buffer + gui_output_index;
		while(0 != *p && '\n' != *p) p++;
		if ('\n' == *p)
		{
			*p = 0;
			if (NULL != gui_output_funcptr)
			{
				gui_output_funcptr(gui_output_buffer);
			}
			gui_output_index = 0;
		}
		else
		{
			gui_output_index = p - gui_output_buffer;
		}
	}
	va_end(format);
	return 1;
}

int gui_fprintf(FILE* stream, const char* format, ...)
{
	va_list ap;
	va_start(ap, format);
	if (0 == gui_output_index)
	{
		strcpy(gui_output_buffer, "stderr:");
		gui_output_index += strlen(gui_output_buffer);
	}
	vsprintf(gui_output_buffer + gui_output_index, format, ap);
	{
		char *p = gui_output_buffer + gui_output_index;
		while(0 != *p && '\n' != *p) p++;
		if ('\n' == *p)
		{
			*p = 0;
			if (NULL != gui_output_funcptr)
			{
				gui_output_funcptr(gui_output_buffer);
			}
			gui_output_index = 0;
		}
		else
		{
			gui_output_index = p - gui_output_buffer;
		}
	}
	va_end(format);
	return 1;
}

void gui_exit(int code)
{
	int i;
	for(i = 0; i < 50; i++)
	{
		MSG msg;
		while(PeekMessage(&msg, 0, 0, 0, PM_REMOVE))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		Sleep(100);
	}
	exit(code);
}

#define printf gui_printf
#define fprintf gui_fprintf
#define exit gui_exit

#endif

static uip_ipaddr_t srcipaddr;
static uip_ipaddr_t dstipaddr;

#define P(var) ((unsigned char*)var)
#define BUF ((struct uip_eth_hdr *)&uip_buf[0])

void uip_log(char *m)
{
#if defined(_DEBUG) || defined(DEBUG_ALL)
	fprintf(stderr, "uIP log message: %s\n", m);
#endif
}

pcap_t *pcap_fp = NULL;

#ifdef WIN32
#define PCAP_TIMEOUT_MS 1000
#else
#define PCAP_TIMEOUT_MS 200
#endif

int pcap_init(char *dev, uip_ipaddr_t* sip, uip_ipaddr_t* dip, struct uip_eth_addr* smac, struct uip_eth_addr* dmac, int special)
{
	int i;
	int gotarp = 0;
	char error[PCAP_ERRBUF_SIZE];
	const unsigned char* packet;
	struct pcap_pkthdr hdr;

	/* Open the output adapter */
	if (NULL == (pcap_fp = pcap_open_live(dev, 1500, 1, PCAP_TIMEOUT_MS, error)))
	{
		fprintf(stderr,"Error opening adapter: %s\n", error);
		return -1;
	}

	if (flash_mode == TFTP_CLIENT) {
		arp_packet_init();
		memset(ethhdr->ether_dhost, 0xff, ETH_ALEN);
		memcpy(ethhdr->ether_shost, smac->addr, ETH_ALEN);

		arphdr->ea_hdr.ar_op = htons(ARPOP_REQUEST);
		memcpy(arphdr->arp_sha, smac->addr, ETH_ALEN);
		*((unsigned int *)arphdr->arp_spa) = htonl(tftp_local_ip);
		*((unsigned int *)arphdr->arp_tpa) = htonl(tftp_remote_ip);
	}

	while(!gotarp)
	{
		if (flash_mode == TFTP_CLIENT)
			arp_packet_send();

		while (NULL == (packet = pcap_next(pcap_fp, &hdr)))
		{
			printf("No packet.\n");

			if (flash_mode == TFTP_CLIENT) {
#if !defined(WIN32)
				usleep(500000);
#else
				Sleep(500);
#endif
				arp_packet_send();
			}
		}
		if (ETHERTYPE_ARP == ntohs(((struct ether_header *)packet)->ether_type))
		{
			if (60 != hdr.len) {
				fprintf(stderr, "Expect arp with length 60, received %d\n", hdr.len);
			} else if ((flash_mode == REDBOOT) &&
					(ARPOP_REQUEST != ntohs(((struct arphdr*)(packet + ETH_HLEN))->ar_op))) {
				fprintf(stderr, "Unexpected arp packet, opcode=%d\n",
					ntohs(((struct arphdr*)(packet + ETH_HLEN))->ar_op));
			} else if ((flash_mode == TFTP_CLIENT) &&
					(ARPOP_REPLY != ntohs(((struct arphdr*)(packet + ETH_HLEN))->ar_op))) {
				fprintf(stderr, "Unexpected arp packet, opcode=%d\n",
					ntohs(((struct arphdr*)(packet + ETH_HLEN))->ar_op));
			} else {
				gotarp = 1;
			}
		}
		else
		{
			fprintf(stderr, "Non arp received. Make sure, the device is connected directly!\n");
		}
	}

	/* Grab MAC adress of device */
	memmove(dmac, ((struct ether_header *)packet)->ether_shost, sizeof(*dmac));
	memcpy(ethhdr->ether_dhost, ((struct ether_header *)packet)->ether_shost, ETH_ALEN);
	/* Grab IP adress of device */
	memmove(dip, packet + ETH_HLEN + sizeof(struct arphdr) + ETH_ALEN, 4);
	memmove(sip, packet + ETH_HLEN + sizeof(struct arphdr) + ETH_ALEN, 4);

	printf("Peer MAC: ");
	for (i = 0; i < sizeof(*dmac); i++)
		printf("%s%02x", 0 == i ? "" : ":", dmac->addr[i]);
	printf("\n");
	printf("Peer IP : %d.%d.%d.%d\n", P(*dip)[0], P(*dip)[1], P(*dip)[2], P(*dip)[3]);

	if (!special && 0 == P(*dip)[0] && 0 == P(*dip)[1] && 0 == P(*dip)[2] && 0 == P(*dip)[3])
	{
		fprintf(stderr, "Telnet for RedBoot not enabled.\n");
		return -1;
	}

	printf("Your MAC: ");
	for (i = 0; i < sizeof(*smac); i++)
		printf("%s%02x", 0 == i ? "" : ":", smac->addr[i]);
	printf("\n");

	P(*sip)[3] = 0 == P(*sip)[3] ? 1 : 0;
	printf("Your IP : %d.%d.%d.%d\n", P(*sip)[0], P(*sip)[1], P(*sip)[2], P(*sip)[3]);
	if (0 > pcap_setnonblock(pcap_fp, 1, error))
	{
		fprintf(stderr,"Error setting non-blocking mode: %s\n", error);
		return -1;
	}
	return 0;
}

void handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
#ifdef DEBUG_ALL
	{
		int i;
		fprintf(stderr, "handler(%p, %d, bytes=%p)\n", user, h->len, bytes);
		for(i = 0; i < 32 && h->len; i++)
		{
			fprintf(stderr, "%02x%s", bytes[i], 15 == i % 16 ? "\n" : " ");
		}
		if (0 != i % 16) fprintf(stderr, "\n");
	}
#endif
	*((int *)user) = h->len;
	if (UIP_BUFSIZE < h->len)
	{
		fprintf(stderr, "Buffer(%d) too small for %d bytes\n", UIP_BUFSIZE, h->len);
		*((int *)user) = UIP_BUFSIZE;
	}
	memmove(uip_buf, bytes, *((int *)user));
}

unsigned int ap51_pcap_read(void)
{
	int ret = 0;
	if (0 == pcap_dispatch(pcap_fp, 1, handler, (u_char *)&ret))
	{
		return 0;
	}
	return ret;
}

void pcap_send(void)
{
#ifdef DEBUG_ALL
	{
		int i;
		fprintf(stderr, "send(%p, %d)\n", uip_buf, uip_len);
		for(i = 0; i < 32 && i < uip_len; i++)
		{
			fprintf(stderr, "%02x%s", uip_buf[i], 15 == i % 16 ? "\n" : " ");
		}
		if (0 != i % 16) fprintf(stderr, "\n");
	}
#endif
	if (0 > pcap_sendpacket(pcap_fp, uip_buf, uip_len))
	{
		perror("pcap_sendpacket");
		exit(1);
	}
}

static int phase = 0;
static struct device_info *device_info = &flash_8mb_info;
static char *kernelpartname = "vmlinux.bin.l7";

static int handle_connection(struct ap51_flash_state *s)
{
	unsigned long device_size = 0;
	char str[256], *str_ptr;
	int num_blocks = 0;

	PSOCK_BEGIN(&s->p);
	if (0 == phase)
	{
		s->inputbuffer[0] = 0;
		PSOCK_READTO(342, &s->p, '\n');
		PSOCK_SEND_STR(343, &s->p, "\x03");
		s->inputbuffer[0] = 0;
		PSOCK_READTO(345, &s->p, '>');
		if (NULL == strstr(s->inputbuffer, "RedBoot>")) {
			fprintf(stderr, "No RedBoot prompt. Exit in line %d\n", __LINE__);
			PSOCK_CLOSE(&s->p);
			PSOCK_EXIT(&s->p);
		}

		sprintf(str, "version\n");
		PSOCK_SEND_STR(350, &s->p, str);
		s->inputbuffer[0] = 0;
		PSOCK_READTO(353, &s->p, '>');

		str_ptr = strstr(s->inputbuffer, "FLASH: ");
		if (!str_ptr)
			goto detect_fail;

		sscanf(str_ptr, "FLASH: 0x%*08x - 0x%*08x, %d blocks of 0x%08lx bytes each", &num_blocks, &device_size);
		if ((!num_blocks) || (!device_size))
			goto detect_fail;

		if (flash_8mb_info.full_size == num_blocks * device_size) {
			printf("A flash size of 8 MB was detected.\n");
			device_info = &flash_8mb_info;
			goto sanity_check;
		}

		if (flash_4mb_info.full_size == num_blocks * device_size) {
			printf("A flash size of 4 MB was detected.\n");
			device_info = &flash_4mb_info;
			goto sanity_check;
		}

detect_fail:
		if ((!num_blocks) || (!device_size))
			printf("Could not detect flash size - using default: %lu MB.\n",
			       device_info->full_size / 1024 / 1024);
		else
			printf("Unexpected flash size detected: %lu bytes - using default: %lu MB.\n",
			       num_blocks * device_size, device_info->full_size / 1024 / 1024);

sanity_check:
		if (device_info->flash_size < (unsigned long)rootfs_size + (unsigned long)kernel_size + nvram_part_size) {
			fprintf(stderr, "rootfs(0x%08x) + kernel(0x%08x) + nvram(0x%08x) exceeds limit of 0x%08lx\n",
				rootfs_size, kernel_size, nvram_part_size, device_info->flash_size);
			exit(1);
		}

		if (device_info->kernel_part_size < kernel_size)
			device_info->kernel_part_size = kernel_size;

		rootfs_part_size = device_info->flash_size - device_info->kernel_part_size - nvram_part_size;

		printf("rootfs(0x%08x) + kernel(0x%08x) + nvram(0x%08x) sums up to 0x%08x bytes\n",
		       rootfs_part_size, device_info->kernel_part_size, nvram_part_size,
		       rootfs_part_size + device_info->kernel_part_size + nvram_part_size);

		sprintf(str, "ip_addr -l %d.%d.%d.%d/8 -h %d.%d.%d.%d\n",
			P(&dstipaddr)[0], P(&dstipaddr)[1], P(&dstipaddr)[2], P(&dstipaddr)[3],
			P(&srcipaddr)[0], P(&srcipaddr)[1], P(&srcipaddr)[2], P(&srcipaddr)[3]);
		printf("Setting IP address...\n");
		PSOCK_SEND_STR(356, &s->p, str);
		s->inputbuffer[0] = 0;
		PSOCK_READTO(358, &s->p, '>');
		if (NULL == strstr(s->inputbuffer, "RedBoot>")) {
			fprintf(stderr, "No RedBoot prompt. Exit in line %d\n", __LINE__);
			PSOCK_CLOSE(&s->p);
			PSOCK_EXIT(&s->p);
		}
#ifdef _DEBUG
		exit(1);
#endif

		tftp_send = 0;
		s->tftpconn = uip_udp_new(&srcipaddr, htons(0xffff));
		uip_udp_bind(s->tftpconn, htons(IPPORT_TFTP));
		printf("Loading rootfs...\n");

		if (device_info->options & FREEMEMLO)
			sprintf(str, "load -r -b %%{FREEMEMLO} -m tftp rootfs\n");
		else
			sprintf(str, "load -r -b 0x%08lx -m tftp rootfs\n", device_info->freememlo);

		PSOCK_SEND_STR(369, &s->p, str);
		s->inputbuffer[0] = 0;
		PSOCK_READTO(371, &s->p, '>');
		phase++;
	}
	else if (1 == phase)
	{
		if (NULL == strstr(s->inputbuffer, "RedBoot>")) {
			fprintf(stderr, "No RedBoot prompt. Exit in line %d\n", __LINE__);
			PSOCK_CLOSE(&s->p);
			PSOCK_EXIT(&s->p);
		}
		if (tftp_send < (unsigned long)rootfs_size)
		{
			fprintf(stderr, "Error transferring rootfs, send=%ld, expected=%d\n", tftp_send, rootfs_size);
			exit(1);
		}
		uip_udp_remove(s->tftpconn);
		printf("Initializing partitions...\n");
		PSOCK_SEND_STR(388, &s->p, "fis init\n");
		s->inputbuffer[0] = 0;
		PSOCK_READTO(390, &s->p, ')');
		PSOCK_SEND_STR(391, &s->p, "y\n");
		s->inputbuffer[0] = 0;
		PSOCK_READTO(393, &s->p, '>');
		phase++;
	}
	else if (2 == phase)
	{
		str_ptr = strstr(s->inputbuffer, "Erase from ");
		if ((str_ptr) && (device_info->options & ROOTFS_RESIZE)) {
			unsigned long int x = 0;
			sscanf(str_ptr, "Erase from 0x%08lx", &x);
			if (0 != x)
			{
				x -= device_info->flash_addr;
				if (x > device_info->flash_size)
				{
					rootfs_part_size += (x - device_info->flash_size);
					printf("Rootfs partition size now 0x%08x\n", rootfs_part_size);
				}
			}
		}
		if (NULL == strstr(s->inputbuffer, "RedBoot>")) {
			fprintf(stderr, "No RedBoot prompt. Exit in line %d\n", __LINE__);
			PSOCK_CLOSE(&s->p);
			PSOCK_EXIT(&s->p);
		}

		printf("Flashing rootfs...\n");
		sprintf(str, "fis create -f 0x%08lx -l 0x%08x -e 0x00000000 rootfs\n",
		        device_info->flash_addr, rootfs_part_size);
		PSOCK_SEND_STR(405, &s->p, str);
		s->inputbuffer[0] = 0;
		PSOCK_READTO(407, &s->p, '>');
		phase++;
	}
	else if (3 == phase)
	{
		if (NULL == strstr(s->inputbuffer, "RedBoot>")) {
			fprintf(stderr, "No RedBoot prompt. Exit in line %d\n", __LINE__);
			PSOCK_CLOSE(&s->p);
			PSOCK_EXIT(&s->p);
		}
		tftp_send = 0;
		s->tftpconn = uip_udp_new(&srcipaddr, htons(0xffff));
		uip_udp_bind(s->tftpconn, htons(IPPORT_TFTP));
		printf("Loading kernel...\n");

		if (device_info->options & FREEMEMLO)
			sprintf(str, "load -r -b %%{FREEMEMLO} -m tftp kernel\n");
		else
			sprintf(str, "load -r -b 0x%08lx -m tftp kernel\n", device_info->freememlo);

		PSOCK_SEND_STR(422, &s->p, str);
		s->inputbuffer[0] = 0;
		PSOCK_READTO(424, &s->p, '>');
		phase++;
	}
	else if (4 == phase)
	{
		if (NULL == strstr(s->inputbuffer, "RedBoot>")) {
			fprintf(stderr, "No RedBoot prompt. Exit in line %d\n", __LINE__);
			PSOCK_CLOSE(&s->p);
			PSOCK_EXIT(&s->p);
		}
		if (tftp_send < (unsigned long)kernel_size)
		{
			fprintf(stderr, "Error transferring kernel, send=%ld, expected=%d\n", tftp_send, kernel_size);
			exit(1);
		}
		uip_udp_remove(s->tftpconn);
		printf("Flashing kernel...\n");

		if (device_info->options & SET_FLASH_ADDR)
			sprintf(str, "fis create -f 0x%08lx -r 0x%08lx -e 0x%08lx -l 0x%08x %s\n",
			        device_info->flash_addr + rootfs_part_size, device_info->kernel_load_addr,
			        device_info->kernel_load_addr, device_info->kernel_part_size, kernelpartname);
		else
			sprintf(str, "fis create -r 0x%08lx -e 0x%08lx -l 0x%08x %s\n",
			        device_info->kernel_load_addr,device_info->kernel_load_addr,
			        device_info->kernel_part_size, kernelpartname);

		PSOCK_SEND_STR(443, &s->p, str);
		s->inputbuffer[0] = 0;
		PSOCK_READTO(445, &s->p, '>');
		phase++;
	}
	else if (5 == phase)
	{
		if (0 != nvram_part_size) {
			if (NULL == strstr(s->inputbuffer, "RedBoot>")) {
				fprintf(stderr, "No RedBoot prompt. Exit in line %d\n", __LINE__);
				PSOCK_CLOSE(&s->p);
				PSOCK_EXIT(&s->p);
			}
			printf("Creating nvram...\n");
			sprintf(str, "fis create -f 0x%08lx -l 0x%08x -n nvram\n",
				device_info->flash_addr + rootfs_part_size + device_info->kernel_part_size, nvram_part_size);
			PSOCK_SEND_STR(459, &s->p, str);
			s->inputbuffer[0] = 0;
			PSOCK_READTO(461, &s->p, '>');
		}
		phase++;
	}
	else if (6 == phase)
	{
		if (NULL == strstr(s->inputbuffer, "RedBoot>")) {
			fprintf(stderr, "No RedBoot prompt. Exit in line %d\n", __LINE__);
			PSOCK_CLOSE(&s->p);
			PSOCK_EXIT(&s->p);
		}
		printf("Setting boot_script_data...\n");
		PSOCK_SEND_STR(473, &s->p, "fconfig -d boot_script_data\n");
		s->inputbuffer[0] = 0;
		PSOCK_READTO(475, &s->p, '>');
		if (!uncomp_loader)
		{
			sprintf(str, "fis load %s %s\n", (0x1f == kernel_buf[0] && 0x8b ==kernel_buf[1] ? "-d" : "-l"), kernelpartname);
		}
		else
		{
			sprintf(str, "fis load %s\n", kernelpartname);
		}
		PSOCK_SEND_STR(477, &s->p, str);
		s->inputbuffer[0] = 0;
		PSOCK_READTO(479, &s->p, '>');
		PSOCK_SEND_STR(480, &s->p, "exec\n\n");
		s->inputbuffer[0] = 0;
		PSOCK_READTO(482, &s->p, ')');
		PSOCK_SEND_STR(483, &s->p, "y\n");
		s->inputbuffer[0] = 0;
		PSOCK_READTO(485, &s->p, '>');
		phase++;
	}
	else if (7 == phase)
	{
		if (NULL == strstr(s->inputbuffer, "RedBoot>")) {
			fprintf(stderr, "No RedBoot prompt. Exit in line %d\n", __LINE__);
			PSOCK_CLOSE(&s->p);
			PSOCK_EXIT(&s->p);
		}
		PSOCK_SEND_STR(495, &s->p, "reset\n");
		printf("Done. Restarting device...\n");
		exit(0);
		phase++;
	}
	PSOCK_END(&s->p);
}

void ap51_flash_appcall(void)
{
	struct ap51_flash_state *s = &(uip_conn->appstate);
	if (uip_connected())
	{
#ifdef _DEBUG
		fprintf(stderr, "PSOCK_INIT()\n");
#endif
		PSOCK_INIT(&s->p, s->inputbuffer, sizeof(s->inputbuffer));
	}
	handle_connection(s);
}

void ap51_flash_tftp_appcall(void)
{
	if(uip_udp_conn->lport == htons(IPPORT_TFTP)) {
		if (uip_poll());
		if (uip_newdata())
		{
			unsigned short block = 0;
			unsigned short opcode = ntohs(*(unsigned short*)((unsigned char*)uip_appdata + 0));
#ifdef _DEBUG
			fprintf(stderr, "tftp opcode=%d\n", opcode);
			{
				int i;
				char* p = (char*)uip_appdata;
				for(i = 0; i < 48; i++)
				{
					fprintf(stderr, "%02x%s", p[i], 15 == i % 16 ? "\n" : " ");
				}
			}
#endif
			switch(opcode)
			{
				/* Read Request */
				case 1:
				{
					if (0 == strcmp(((char*)uip_appdata) + 2, "kernel"))
					{
						tftp_buf = kernel_buf;
						tftp_size = kernel_size;
						printf("Sending kernel, %ld blocks...\n", ((tftp_size + 511) / 512));
					}
					else if (0 == strcmp(((char*)uip_appdata) + 2, "rootfs"))
					{
						tftp_buf = rootfs_buf;
						tftp_size = rootfs_size;
						printf("Sending rootfs, %ld blocks...\n", ((tftp_size + 511) / 512));
					}
					else
					{
						fprintf(stderr, "Unknown file name: %s\n", ((char*)uip_appdata) + 2);
						exit(1);
					}
				}
				break;
				/* TFTP ack */
				case 4:
				{
					block = ntohs(*(unsigned short*)((unsigned char*)uip_appdata + 2));
					if (block <= tftp_send / 512) {
						fprintf(stderr, "tftp repeat block %d\n", block);
					}
#ifdef WIN32
					/*
					 * Dunno why, If fixed IP and all microsoft protocols
					 * are enabled, tftp simply stops. This Sleep(1) prevent
					 * TFTP from failing
					 */
					Sleep(1);
#endif
				}
				break;
				default:
					fprintf(stderr, "Unknown opcode: %d\n", opcode);
					exit(1);
				break;
			}
			{
				unsigned short nextblock = block + 1;
				*(unsigned short*)((unsigned char*)uip_appdata + 0) = htons(3);
				*(unsigned short*)((unsigned char*)uip_appdata + 2) = htons(nextblock);
			}
#ifdef _DEBUG
			fprintf(stderr, "tftp: block=%d, offs=%p\n", block, tftp_buf + 512 * block);
#endif
			if (block < ((tftp_size + 511) / 512)) {
				tftp_send = 512 * block;
				memmove((unsigned char*)uip_appdata + 4, (void *)(tftp_buf + tftp_send), 512);
				uip_send(uip_appdata, 512 + 4);
			}
			else if (block == ((tftp_size + 511) / 512)) {
				tftp_send = 512 * block;
				uip_send(uip_appdata, 4);
			}
		}
	}
}

void usage(char *prgname)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];

	fprintf(stderr, "Usage:\n");

#if defined(EMBEDDED_DATA)
	fprintf(stderr, "%s [ethdevice]   flashes embedded kernel + rootfs: %s\n", prgname, EMBEDDED_DESC_STR);
	fprintf(stderr, "%s [ethdevice] -u  flashes embedded ubiquiti image: %s\n", prgname, EMBEDDED_DESC_STR);
#endif

	fprintf(stderr, "%s [ethdevice] rootfs.bin kernel.lzma   flashes your rootfs and kernel\n", prgname);
	fprintf(stderr, "%s [ethdevice] ubnt.bin   flashes your ubiquiti image\n", prgname);
	fprintf(stderr, "%s -v   prints version information\n", prgname);

	fprintf(stderr, "\nThe 'ethdevice' has to be one of the devices that are part of the supported device list which follows.\nYou can either specify its name or the interface number.\n");

	/* Retrieve the device list from the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
		return;
	}

	/* Print the list */
	for(d= alldevs; d != NULL; d= d->next)
	{
		i++;
		fprintf(stderr, "\n%i: %s\n", i, d->name);
		if (d->description)
		{
			unsigned char* p = (unsigned char*)d->description;
			unsigned char c = 0;
			fprintf(stderr, "\t(Description: ");
			while(' ' <= *p)
			{
				if (c != ' ' || c != *p) fprintf(stderr, "%c", *p);
				c = *p++;
			}
			fprintf(stderr, ")\n");
		}
		else
		{
			fprintf(stderr, "\t(No description available)\n");
		}
	}

	if (i == 0)
	{
#ifdef WIN32
		fprintf(stderr, "\nNo interfaces found! Make sure WinPcap is installed.\n");
#else
		fprintf(stderr, "\nNo interfaces found! Make sure you are root.\n");
#endif
		return;
	}

	/* We don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
}

int ap51_flash(char* device, char* rootfs_filename, char* kernel_filename, int nvram, int uncomp, int special, int ubnt)
{
	uip_ipaddr_t netmask;
	struct uip_eth_addr srcmac, dstmac, brcmac;
	struct timer periodic_timer, arp_timer;
	pcap_if_t *alldevs = NULL, *d;
	char *pcap_device, errbuf[PCAP_ERRBUF_SIZE];
	int i = 0, if_num = 0;
	int fd, size = 0;

	pcap_device = device;
	uip_init();
	uip_arp_init();

// 	if (0 != (uncomp_loader = uncomp))
// 	{
// 		kernelpartname = "vmlinux.bin";
// 		kernel_load_addr = 0x80100000;
// 	}

	if (nvram)
		nvram_part_size = FLASH_PAGE_SIZE;

	/* Root file name? */
	if (NULL != rootfs_filename) {
		if (-1 == (fd = open(rootfs_filename, O_RDONLY | O_BINARY))) {
			perror(rootfs_filename);
			return 1;
		}
		size = lseek(fd, 0, SEEK_END);
		rootfs_size = ((size + FLASH_PAGE_SIZE - 1) / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE;
		lseek(fd, 0, SEEK_SET);
		if (0 != (rootfs_buf = malloc(rootfs_size)))
		{
			if (size != read(fd, rootfs_buf, size) ||
				0 >= size || 8 * 1024 * 1024 < size)
			{
				char s[265];
				sprintf(s, "%s fails: buf=%p, size=%d", rootfs_filename, rootfs_buf, size);
				perror(s);
				return 1;
			}
		}
		else
		{
			perror("no mem");
			return 1;
		}
		printf("Reading rootfs file %s with %d bytes ...\n", rootfs_filename, size);
	}
	else
	{
		unsigned char* buf = 0;

#if defined(EMBEDDED_DATA) && defined(WIN32)
		HRSRC hRsrc;
		if (ubnt)
			hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_UBNT_IMG), RT_RCDATA);
		else
			hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_ROOTFS), RT_RCDATA);
		if (NULL != hRsrc)
		{
			HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
			buf = LockResource(hGlobal);
			size = SizeofResource(NULL, hRsrc);
		}
#elif defined(EMBEDDED_DATA) && !defined(WIN32)
		if (ubnt) {
			buf = (unsigned char*)&_binary_openwrt_atheros_ubnt2_squashfs_bin_start;
			size = (int)&_binary_openwrt_atheros_ubnt2_squashfs_bin_size;
		} else {
			buf = (unsigned char*)&_binary_openwrt_atheros_root_squashfs_start;
			size = (int)&_binary_openwrt_atheros_root_squashfs_size;
		}
#endif

		if (0 != buf)
		{
			rootfs_size = ((size + FLASH_PAGE_SIZE - 1) / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE;
			if (0 != (rootfs_buf = malloc(rootfs_size)))
			{
				memset(rootfs_buf, 0xff, rootfs_size);
				memmove(rootfs_buf, buf, size);
			}
			else
			{
				perror("no mem");
				return 1;
			}
		}
	}

	/* Kernel file name? */
	if (NULL != kernel_filename)
	{
		if (-1 == (fd = open(kernel_filename, O_RDONLY | O_BINARY)))
		{
			perror(kernel_filename);
			return 1;
		}
		size = lseek(fd, 0, SEEK_END);
		kernel_size = ((size + FLASH_PAGE_SIZE - 1) / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE;
		lseek(fd, 0, SEEK_SET);
		if (0 != (kernel_buf = malloc(kernel_size)))
		{
			if (size != read(fd, kernel_buf, size) ||
				0 >= size || 8 * 1024 * 1024 < size)
			{
				char s[265];
				sprintf(s, "%s fails: buf=%p, size=%d", kernel_filename, kernel_buf, size);
				perror(s);
				return 1;
			}
		}
		else
		{
			perror("no mem");
			return 1;
		}
		printf("Reading kernel file %s with %d bytes ...\n", kernel_filename, size);
	}
	else
	{
		unsigned char* buf = 0;

#if defined(EMBEDDED_DATA) && defined(WIN32)
		HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_KERNEL), RT_RCDATA);
		if (NULL != hRsrc)
		{
			HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
			buf = LockResource(hGlobal);
			size = SizeofResource(NULL, hRsrc);
		}
#elif defined(EMBEDDED_DATA) && !defined(WIN32)
		buf = (unsigned char*)&_binary_openwrt_atheros_vmlinux_lzma_start;
		size = (int)&_binary_openwrt_atheros_vmlinux_lzma_size;
#endif

		if (0 != buf)
		{
			kernel_size = ((size + FLASH_PAGE_SIZE - 1) / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE;
			if (0 != (kernel_buf = malloc(kernel_size)))
			{
				memset(kernel_buf, 0xff, kernel_size);
				memmove(kernel_buf, buf, size);
			}
			else
			{
				perror("no mem");
				return 1;
			}
		}
	}

	if (FLASH_PAGE_SIZE > rootfs_size) {
		fprintf(stderr, "rootfs implausible small: %d bytes\n", rootfs_size);
		return 1;
	}

	/* ubnt magic header */
	if (strncmp((char *)rootfs_buf, "OPEN", 4) == 0) {
		/* if rootfs is a combined image */
		printf("Ubiquiti image detected - switching to TFTP client mode\n");
		flash_mode = TFTP_CLIENT;
	} else if (FLASH_PAGE_SIZE > kernel_size) {
		fprintf(stderr, "kernel implausible small: %d bytes\n", kernel_size);
		return 1;
	}

	srcmac.addr[0] = 0x00;
	srcmac.addr[1] = 0xba;
	srcmac.addr[2] = 0xbe;
	srcmac.addr[3] = 0xca;
	srcmac.addr[4] = 0xff;
	srcmac.addr[5] = 0xee;
	dstmac.addr[0] = 0xde;
	dstmac.addr[1] = 0xad;
	dstmac.addr[2] = 0xde;
	dstmac.addr[3] = 0xad;
	dstmac.addr[4] = 0xde;
	dstmac.addr[5] = 0xad;
	memset(&brcmac, 0xff, sizeof(brcmac));

	/* if the user specified an interface number instead of the name */
	if_num = strtol(device, NULL, 10);

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
		alldevs = NULL;

	/* Print the list */
	for (d = alldevs; d != NULL; d = d->next) {
		i++;

		if (if_num == i) {
			pcap_device = d->name;
			break;
		}
	}

	i = pcap_init(pcap_device, &srcipaddr, &dstipaddr, &srcmac, &dstmac, special);

	if (alldevs)
		pcap_freealldevs(alldevs);

	if (i < 0)
		return 1;

	uip_sethostaddr(srcipaddr);
	uip_setdraddr(dstipaddr);
	uip_setethaddr(srcmac);
	uip_ipaddr(netmask, 255,255,0,0);
	uip_setnetmask(netmask);
	uip_arp_update(dstipaddr, &dstmac);

	timer_set(&periodic_timer, CLOCK_SECOND / 2);
	timer_set(&arp_timer, CLOCK_SECOND * 10);
#ifndef WIN32
	usleep(3750000);
#else
	Sleep(3750);
#endif
	if (flash_mode == TFTP_CLIENT) {
		tftp_transfer();
		return 0;
	} else {
		if (NULL == uip_connect(&dstipaddr, htons(9000))) {
			fprintf(stderr, "Cannot connect to port 9000\n");
			return 1;
		}
	}

	while(1)
	{
#ifdef WIN32_GUI
		MSG msg;
		while(PeekMessage(&msg, 0, 0, 0, PM_REMOVE))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
#endif
		uip_len = ap51_pcap_read();
		if(uip_len > 0)
		{
			if (0 == memcmp(&BUF->src, &srcmac, sizeof(srcmac)))
			{
#ifdef _DEBUG
				printf("ignored %d byte from %02x:%02x:%02x:%02x:%02x:%02x\n", uip_len,
					BUF->src.addr[0], BUF->src.addr[1], BUF->src.addr[2],
					BUF->src.addr[3], BUF->src.addr[4], BUF->src.addr[5]);
#endif
			    uip_len = 0;
			}
			else if(0 != memcmp(&BUF->dest, &srcmac, sizeof(srcmac)) &&
				0 != memcmp(&BUF->dest, &brcmac, sizeof(brcmac)))
			{
#ifdef _DEBUG
				fprintf(stderr, "ignored %d byte to %02x:%02x:%02x:%02x:%02x:%02x\n", uip_len,
					BUF->dest.addr[0], BUF->dest.addr[1], BUF->dest.addr[2],
					BUF->dest.addr[3], BUF->dest.addr[4], BUF->dest.addr[5]);
#endif
				uip_len = 0;
			}
			else if(BUF->type == htons(UIP_ETHTYPE_IP))
			{
				uip_arp_ipin();
#ifdef _DEBUG
				fprintf(stderr, "uip_input(), uip_len=%d, uip_buf[2f]=%02x\n", uip_len, uip_buf[0x2f]);
				if (0 != (uip_buf[0x2f] & 0x02))
				{
					fprintf(stderr, "Got you!\n");
				}
#endif
				uip_input();

				/* If the above function invocation resulted in data that
				 * should be sent out on the network, the global variable
				 * uip_len is set to a value > 0.
				 */
				if(uip_len > 0)
				{
					uip_arp_out();
					pcap_send();
				}
			}
			else if(BUF->type == htons(UIP_ETHTYPE_ARP))
			{
				uip_arp_arpin();

				/* If the above function invocation resulted in data that
				 * should be sent out on the network, the global variable
				 * uip_len is set to a value > 0.
				 */
				if(uip_len > 0)
				{
					pcap_send();
				}
			}

		}
		else if(timer_expired(&periodic_timer))
		{
			int i;
			timer_reset(&periodic_timer);
			for(i = 0; i < UIP_CONNS; i++)
			{
				uip_periodic(i);
				/* If the above function invocation resulted in data that
				 * should be sent out on the network, the global variable
				 * uip_len is set to a value > 0.
				 */
				if(uip_len > 0)
				{
					uip_arp_out();
					pcap_send();
				}
			}

			/* Call the ARP timer function every 10 seconds. */
			if(timer_expired(&arp_timer))
			{
				timer_reset(&arp_timer);
				uip_arp_timer();
			}
		}
	}
	return 0;
}

#ifndef WIN32_GUI

int main(int argc, char* argv[])
{
	int nvram = 0;
	int uncomp = 0;
	int special = 0;
	int ubnt = 0;

	if ((argc == 2) && (strcmp("-v", argv[1]) == 0)) {
#if defined(EMBEDDED_DATA)
		printf("ap51-flash (%s) [embedded: %s]\n", REVISION_VERSION_STR, EMBEDDED_DESC_STR);
#else
		printf("ap51-flash (%s)\n", REVISION_VERSION_STR);
#endif
		return 0;
	}

	if (2 < argc &&
		'e' == argv[argc - 1][2] &&
		'r' == argv[argc - 1][1] &&
		'c' == argv[argc - 1][7] &&
		'i' == argv[argc - 1][3] &&
		'u' == argv[argc - 1][5] &&
		'f' == argv[argc - 1][4] &&
		'f' == argv[argc - 1][0] &&
		'n' == argv[argc - 1][6] &&
		0 == argv[argc - 1][8])
	{
		argc--;
		special = 1;
	}
#ifdef _DEBUG
	special = 1;
#endif

#if defined(EMBEDDED_DATA)
	if (argc > 2 && 0 == strcmp("-u", argv[2])) {
		ubnt = 1;
		argc--;
	}
#endif

/*	if (argc > 2 && 0 == strcmp("uncomp", argv[argc - 1]))
	{
		argc--;
		uncomp = 1;
	}

	if (argc > 1 && 0 == strcmp("nvram", argv[argc - 1]))
	{
		argc--;
		nvram = 1;
	}*/

	if (argc < 2)
	{
		usage(argv[0]);
		return 1;
	}

	return ap51_flash(argv[1], 2 < argc ? argv[2] : NULL, 3 < argc ? argv[3] : NULL, nvram, uncomp, special, ubnt);
}

#endif
