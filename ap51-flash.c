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

unsigned char *kernel_buf = 0;
unsigned char *rootfs_buf = 0;

int kernel_size = 0;
int rootfs_size = 0;

static int uncomp_loader = 0;
static int nvram_part_size = 0x00000000;
static int rootfs_part_size = 0x00000000;

char flash_mode = MODE_NONE;
unsigned int remote_ip;
unsigned int local_ip;
static unsigned int ubnt_remote_ip = 3232235796UL; /* 192.168.1.20 */
static unsigned int ubnt_local_ip = 3232235801UL; /* 192.168.1.25 */
unsigned char *tftp_xfer_buff = NULL;
unsigned long tftp_xfer_size = 0;

static char boot_prompt[24];
static int phase = 0;
static struct device_info *device_info = &flash_8mb_info;
static char *kernelpartname = "vmlinux.bin.l7";
pcap_t *pcap_fp = NULL;

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

static uip_ipaddr_t srcipaddr;
static uip_ipaddr_t dstipaddr;

#define P(var) ((unsigned char*)var)
#define BUF ((struct uip_eth_hdr *)&uip_buf[0])

void uip_log(char *m)
{
#if defined(PACKET_DEBUG)
	fprintf(stderr, "uIP log message: %s\n", m);
#endif
}

static int pcap_init(char *dev, uip_ipaddr_t* sip, uip_ipaddr_t* dip, struct uip_eth_addr* smac, struct uip_eth_addr* dmac, int special)
{
	int arp_replies = 0, arp_grat_packets = 0;
	char error[PCAP_ERRBUF_SIZE];
	const unsigned char *packet;
	struct pcap_pkthdr hdr;
	struct ether_header *recv_ethhdr;
	struct ether_arp *recv_arphdr;
#if defined(DEBUG)
	int i;
#endif

	/* Open the output adapter */
	if (NULL == (pcap_fp = pcap_open_live(dev, 1500, 1, PCAP_TIMEOUT_MS, error))) {
		fprintf(stderr,"Error opening adapter: %s\n", error);
		return -1;
	}

	arp_packet_init();
	memset(ethhdr->ether_dhost, 0xff, ETH_ALEN);
	memcpy(ethhdr->ether_shost, smac->addr, ETH_ALEN);

	arphdr->ea_hdr.ar_op = htons(ARPOP_REQUEST);
	memcpy(arphdr->arp_sha, smac->addr, ETH_ALEN);
	*((unsigned int *)arphdr->arp_spa) = htonl(ubnt_local_ip);
	*((unsigned int *)arphdr->arp_tpa) = htonl(ubnt_remote_ip);

	fprintf(stderr, "Waiting for device to run auto-detection.\nMake sure, the device is connected directly!\n");

	while (1) {
		arp_packet_send();

		while (NULL == (packet = pcap_next(pcap_fp, &hdr))) {
#if defined(DEBUG)
			printf("No packet.\n");
#endif
			usleep(250000);
			arp_packet_send();
		}

		recv_ethhdr = (struct ether_header *)packet;

		if (recv_ethhdr->ether_type != htons(ETHERTYPE_ARP)) {
#if defined(DEBUG)
			fprintf(stderr, "Non arp received. Make sure, the device is connected directly!\n");
#endif
			continue;
		}

		if (hdr.len != 60) {
#if defined(DEBUG)
			fprintf(stderr, "Expect arp with length 60, received %d\n", hdr.len);
#endif
			continue;
		}

		recv_arphdr = (struct ether_arp *)(packet + sizeof(struct ether_header));

		if (recv_arphdr->ea_hdr.ar_op == htons(ARPOP_REPLY)) {
			if (*((unsigned int *)recv_arphdr->arp_spa) != htonl(ubnt_remote_ip)) {
#if defined(DEBUG)
				fprintf(stderr, "Unexpected arp packet, opcode=%d, spa=%u\n",
					ntohs(recv_arphdr->ea_hdr.ar_op),
					ntohl(*((unsigned int *)recv_arphdr->arp_spa)));
#endif
				continue;
			}

			if (arp_replies < 20) {
				arp_replies++;
				usleep(250000);
				continue;
			}

			flash_mode = MODE_TFTP_CLIENT;
			break;
		}

		if (recv_arphdr->ea_hdr.ar_op != htons(ARPOP_REQUEST)) {
#if defined(DEBUG)
			fprintf(stderr, "Unexpected arp packet, opcode=%d\n", ntohs(recv_arphdr->ea_hdr.ar_op));
#endif
			continue;
		}

		/* we are waiting for gratuitous requests */
		if (*((unsigned int *)recv_arphdr->arp_spa) != *((unsigned int *)recv_arphdr->arp_tpa))
			continue;

		/* use gratuitous ARP requests from ubnt devices with care */
		if (*((unsigned int *)recv_arphdr->arp_spa) == htonl(ubnt_remote_ip)) {
			if (arp_grat_packets < 5) {
				arp_grat_packets++;
				continue;
			}

			flash_mode = MODE_MAYBE_REDBOOT;
			break;
		}

		flash_mode = MODE_REDBOOT;
		break;
	}

	/* Grab MAC adress of device */
	memmove(dmac, recv_ethhdr->ether_shost, ETH_ALEN);
	memcpy(ethhdr->ether_dhost, recv_ethhdr->ether_shost, ETH_ALEN);
	/* Grab IP adress of device */
	memmove(dip, recv_arphdr->arp_spa, 4);
	memmove(sip, recv_arphdr->arp_tpa, 4);

	if ((flash_mode == MODE_REDBOOT) || (flash_mode == MODE_MAYBE_REDBOOT))
		P(*sip)[3] = 0 == P(*sip)[3] ? 1 : 0;

	memcpy(&remote_ip, dip, 4);
	memcpy(&local_ip, sip, 4);

	if (!special && 0 == P(*dip)[0] && 0 == P(*dip)[1] && 0 == P(*dip)[2] && 0 == P(*dip)[3]) {
		fprintf(stderr, "Telnet for RedBoot not enabled.\n");
		return -1;
	}

#if defined(DEBUG)
	printf("Peer MAC: ");
	for (i = 0; i < sizeof(*dmac); i++)
		printf("%s%02x", 0 == i ? "" : ":", dmac->addr[i]);
	printf("\n");

	printf("Peer IP : %d.%d.%d.%d\n", P(*dip)[0], P(*dip)[1], P(*dip)[2], P(*dip)[3]);

	printf("Your MAC: ");
	for (i = 0; i < ETH_ALEN; i++)
		printf("%s%02x", 0 == i ? "" : ":", smac->addr[i]);
	printf("\n");

	printf("Your IP : %d.%d.%d.%d\n", P(*sip)[0], P(*sip)[1], P(*sip)[2], P(*sip)[3]);
#endif

	if (0 > pcap_setnonblock(pcap_fp, 1, error)) {
		fprintf(stderr,"Error setting non-blocking mode: %s\n", error);
		return -1;
	}

	return 0;
}

static int extract_boot_prompt(struct ap51_flash_state *s)
{
	char *str_ptr;

	str_ptr = strchr(s->inputbuffer, '>');
	if (!str_ptr) {
		fprintf(stderr, "No RedBoot prompt detected. Exit in line %d\n", __LINE__);
		return -1;
	}

	*(str_ptr + 1) = '\0';

	str_ptr = strrchr(s->inputbuffer, '\n');
	if (!str_ptr) {
		fprintf(stderr, "No RedBoot detected. Exit in line %d\n", __LINE__);
		return -1;
	}

	str_ptr++;

	if (strlen(str_ptr) > sizeof(boot_prompt)) {
		fprintf(stderr, "No RedBoot prompt exceeds expected size (%i - expected %i). Exit in line %d\n",
			strlen(str_ptr), sizeof(boot_prompt), __LINE__);
		return -1;
	}

	memcpy(boot_prompt, str_ptr, sizeof(boot_prompt));
	return 0;
}

static int handle_connection(struct ap51_flash_state *s)
{
	unsigned long device_size = 0;
	char str[256], *str_ptr;
	int num_blocks = 0;

	PSOCK_BEGIN(&s->p);

	/* a case loop would be broken by PSOCK_READTO - WTF */
	if (phase == 0) {
		s->inputbuffer[0] = 0;
		PSOCK_READTO(342, &s->p, '\n');
		PSOCK_SEND_STR(343, &s->p, "\x03");
		s->inputbuffer[0] = 0;
		PSOCK_READTO(345, &s->p, '>');

		if (extract_boot_prompt(s) < 0)
			goto err_close;

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

		if (!strstr(s->inputbuffer, boot_prompt)) {
			fprintf(stderr, "No RedBoot prompt. Exit in line %d\n", __LINE__);
			goto err_close;
		}

		tftp_bytes_sent = 0;
		printf("Loading rootfs...\n");

		if (device_info->options & FREEMEMLO)
			sprintf(str, "load -r -b %%{FREEMEMLO} -m tftp rootfs\n");
		else
			sprintf(str, "load -r -b 0x%08lx -m tftp rootfs\n", device_info->freememlo);

		PSOCK_SEND_STR(369, &s->p, str);
		s->inputbuffer[0] = 0;
		PSOCK_READTO(371, &s->p, '>');
		phase++;

	} else if (phase == 1) {
		if (!strstr(s->inputbuffer, boot_prompt)) {
			fprintf(stderr, "No RedBoot prompt. Exit in line %d\n", __LINE__);
			goto err_close;
		}

		if (tftp_bytes_sent < (unsigned long)rootfs_size) {
			fprintf(stderr, "Error transferring rootfs, send=%ld, expected=%d\n", tftp_bytes_sent, rootfs_size);
			exit(1);
		}

		xfer_in_progress = 0;
		printf("Initializing partitions...\n");
		PSOCK_SEND_STR(388, &s->p, "fis init\n");
		s->inputbuffer[0] = 0;
		PSOCK_READTO(390, &s->p, ')');
		PSOCK_SEND_STR(391, &s->p, "y\n");
		s->inputbuffer[0] = 0;
		PSOCK_READTO(393, &s->p, '>');
		phase++;

	} else if (phase == 2) {
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

		if (!strstr(s->inputbuffer, boot_prompt)) {
			fprintf(stderr, "No RedBoot prompt. Exit in line %d\n", __LINE__);
			goto err_close;
		}

		printf("Flashing rootfs...\n");
		sprintf(str, "fis create -f 0x%08lx -l 0x%08x -e 0x00000000 rootfs\n",
		        device_info->flash_addr, rootfs_part_size);
		PSOCK_SEND_STR(405, &s->p, str);
		s->inputbuffer[0] = 0;
		PSOCK_READTO(407, &s->p, '>');
		phase++;

	} else if (phase == 3) {
		if (!strstr(s->inputbuffer, boot_prompt)) {
			fprintf(stderr, "No RedBoot prompt. Exit in line %d\n", __LINE__);
			goto err_close;
		}

		tftp_bytes_sent = 0;
		printf("Loading kernel...\n");

		if (device_info->options & FREEMEMLO)
			sprintf(str, "load -r -b %%{FREEMEMLO} -m tftp kernel\n");
		else
			sprintf(str, "load -r -b 0x%08lx -m tftp kernel\n", device_info->freememlo);

		PSOCK_SEND_STR(422, &s->p, str);
		s->inputbuffer[0] = 0;
		PSOCK_READTO(424, &s->p, '>');
		phase++;

	} else if (phase == 4) {
		if (!strstr(s->inputbuffer, boot_prompt)) {
			fprintf(stderr, "No RedBoot prompt. Exit in line %d\n", __LINE__);
			goto err_close;
		}
		if (tftp_bytes_sent < (unsigned long)kernel_size)
		{
			fprintf(stderr, "Error transferring kernel, send=%ld, expected=%d\n", tftp_bytes_sent, kernel_size);
			exit(1);
		}

		xfer_in_progress = 0;
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

	} else if (phase == 5) {
		if (0 != nvram_part_size) {
			if (!strstr(s->inputbuffer, boot_prompt)) {
				fprintf(stderr, "No RedBoot prompt. Exit in line %d\n", __LINE__);
				goto err_close;
			}

			printf("Creating nvram...\n");
			sprintf(str, "fis create -f 0x%08lx -l 0x%08x -n nvram\n",
				device_info->flash_addr + rootfs_part_size + device_info->kernel_part_size, nvram_part_size);
			PSOCK_SEND_STR(459, &s->p, str);
			s->inputbuffer[0] = 0;
			PSOCK_READTO(461, &s->p, '>');
		}

		phase++;
		break;

	} else if (phase == 6) {
		if (!strstr(s->inputbuffer, boot_prompt)) {
			fprintf(stderr, "No RedBoot prompt. Exit in line %d\n", __LINE__);
			goto err_close;
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
		break;

	} else if (phase == 7) {
		if (!strstr(s->inputbuffer, boot_prompt)) {
			fprintf(stderr, "No RedBoot prompt. Exit in line %d\n", __LINE__);
			goto err_close;
		}

		PSOCK_SEND_STR(495, &s->p, "reset\n");
		printf("Done. Restarting device...\n");
		exit(0);
		phase++;
		break;
	}

	PSOCK_END(&s->p);
	return 0;

err_close:
	PSOCK_CLOSE(&s->p);
	PSOCK_EXIT(&s->p);
	exit(1);
}

void ap51_flash_appcall(void)
{
	struct ap51_flash_state *s = &(uip_conn->appstate);

	if (uip_connected())
		PSOCK_INIT(&s->p, s->inputbuffer, sizeof(s->inputbuffer));

	handle_connection(s);
}

static void send_uip_buffer(void)
{
	if (uip_len <= 0)
		return;

	if (pcap_sendpacket(pcap_fp, uip_buf, uip_len) < 0) {
		perror("pcap_sendpacket");
		exit(1);
	}
}

void handle_uip_tcp(const unsigned char *packet_buff, unsigned int packet_len)
{
	uip_len = packet_len;

	if (UIP_BUFSIZE < uip_len) {
		fprintf(stderr, "Buffer(%d) too small for %d bytes - truncating\n",
			UIP_BUFSIZE, uip_len);
		uip_len = UIP_BUFSIZE;
	}

	memmove(uip_buf, packet_buff, uip_len);

	uip_arp_ipin();

#if defined(PACKET_DEBUG)
	fprintf(stderr, "uip_input(), uip_len=%d, uip_buf[2f]=%02x\n", uip_len, uip_buf[0x2f]);
	if ((uip_buf[0x2f] & 0x02) != 0)
		fprintf(stderr, "Got you!\n");
#endif

	uip_input();

	/* If the above function invocation resulted in data that
	 * should be sent out on the network, the global variable
	 * uip_len is set to a value > 0.
	 */
	if (uip_len > 0) {
		uip_arp_out();
		send_uip_buffer();
	}
}

void handle_uip_conns(void)
{
	int i;

	for (i = 0; i < UIP_CONNS; i++) {
		uip_periodic(i);
		/* If the above function invocation resulted in data that
			* should be sent out on the network, the global variable
			* uip_len is set to a value > 0.
			*/
		if (uip_len > 0) {
			uip_arp_out();
			send_uip_buffer();
		}
	}
}

int ap51_flash(char* device, char* rootfs_filename, char* kernel_filename, int nvram, int uncomp, int special)
{
	uip_ipaddr_t netmask;
	struct uip_eth_addr srcmac, dstmac, brcmac;
	pcap_if_t *alldevs = NULL, *d;
	char *pcap_device, errbuf[PCAP_ERRBUF_SIZE];
	unsigned char* buf = 0;
	int i = 0, if_num = 0;
	int fd, size = 0, ubnt_img = 0;

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
	} else {
#if defined(EMBEDDED_DATA) && defined(WIN32)
		HRSRC hRsrc;
		hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_ROOTFS), RT_RCDATA);
		if (NULL != hRsrc)
		{
			HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
			buf = LockResource(hGlobal);
			size = SizeofResource(NULL, hRsrc);
		}
#elif defined(EMBEDDED_DATA) && !defined(WIN32)
		buf = (unsigned char*)&_binary_openwrt_atheros_root_squashfs_start;
		size = (int)&_binary_openwrt_atheros_root_squashfs_size;
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
	} else {
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
	if ((strncmp((char *)rootfs_buf, "UBNT", 4) == 0) ||
	    (strncmp((char *)rootfs_buf, "OPEN", 4) == 0))
		ubnt_img = 1;

	if ((FLASH_PAGE_SIZE > kernel_size) && (!ubnt_img)) {
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

	/**
	 * the arp packet count should make sure we get the difference
	 * between the pico and the other ubnt devices
	 **/
	if (flash_mode == MODE_MAYBE_REDBOOT)
		flash_mode = MODE_REDBOOT;

	switch (flash_mode) {
	case MODE_REDBOOT:
		if (ubnt_img) {
			fprintf(stderr, "You are trying to flash a redboot device with a ubiquiti image!\n");
			return 1;
		}

		printf("Redboot enabled device detected - using redboot to flash\n");
		printf("WARNING: UNPLUGGING POWER OR ETHERNET DURING THIS PROCESS WILL LIKELY DAMAGE\n");
		printf("YOUR DEVICE AND THIS WILL NOT BE COVERED BY WARRANTY!\n");

		if (NULL == uip_connect(&dstipaddr, htons(TELNET_PORT))) {
			fprintf(stderr, "Cannot connect to port %i\n", TELNET_PORT);
			return 1;
		}
		break;
	case MODE_TFTP_CLIENT:
#if defined(EMBEDDED_DATA)
		if (!rootfs_filename) {

			/* free the rootfs and replace it by the ubnt image */
			free(rootfs_buf);

#if defined(WIN32)
			HRSRC hRsrc;
			hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_UBNT_IMG), RT_RCDATA);
			if (NULL != hRsrc) {
				HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
				buf = LockResource(hGlobal);
				size = SizeofResource(NULL, hRsrc);
			}
#else
			buf = (unsigned char*)&_binary_openwrt_atheros_ubnt2_squashfs_bin_start;
			size = (int)&_binary_openwrt_atheros_ubnt2_squashfs_bin_size;
#endif

			if (0 != buf) {
				rootfs_size = ((size + FLASH_PAGE_SIZE - 1) / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE;
				if (0 != (rootfs_buf = malloc(rootfs_size))) {
					memset(rootfs_buf, 0xff, rootfs_size);
					memmove(rootfs_buf, buf, size);
				} else {
					perror("no mem");
					return 1;
				}
			}

			ubnt_img = 1;
		}
#endif
		if (!ubnt_img) {
			fprintf(stderr, "You are trying to flash a ubiquiti device with redboot images!\n");
			return 1;
		}

		tftp_xfer_buff = rootfs_buf;
		tftp_xfer_size = rootfs_size;
		printf("Ubiquiti device detected - using TFTP client to flash\n");
		break;
	default:
		fprintf(stderr, "Could not auto-detect flash mode!\n");
		return 1;
	}

	fw_upload();
	return 0;
}

