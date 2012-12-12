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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "types.h"
#include "router_redboot.h"
#include "proto.h"
#include "flash.h"
#include "router_images.h"

#define REDBOOT_STATE_INIT	0x00
#define REDBOOT_STATE_VERSION	0x01
#define REDBOOT_STATE_IP_ADDR	0x02
#define REDBOOT_STATE_LD_KERNEL	0x03
#define REDBOOT_STATE_FL_KERNEL	0x04
#define REDBOOT_STATE_LD_ROOTFS	0x05
#define REDBOOT_STATE_FL_ROOTFS	0x06
#define REDBOOT_STATE_BSCRIPT	0x07
#define REDBOOT_STATE_BSCRIPTK	0x08
#define REDBOOT_STATE_EXEC	0x09
#define REDBOOT_STATE_EXECY	0x10
#define REDBOOT_STATE_RESET	0x11
#define REDBOOT_STATE_FINISHED	0x12
#define REDBOOT_STATE_FIS_INIT	0x50
#define REDBOOT_STATE_FIS_INITY	0x51
#define REDBOOT_STATE_FAILED	0x99

static unsigned int ubnt_ip = 3232235796UL; /* 192.168.1.20 */

struct redboot_priv {
	int arp_count;
	int redboot_state;
	struct redboot_type *redboot_type;
	char *version_info;
};

static int redboot_8mb_detect(struct node *node)
{
	struct redboot_priv *redboot_priv = node->router_priv;
	unsigned long device_size = 0;
	char *flash_str;
	int num_blocks = 0, ret = 0;

	flash_str = strstr(redboot_priv->version_info, "FLASH:");
	if (!flash_str)
		goto out;

	sscanf(flash_str, "FLASH: 0x%*08x - 0x%*08x, %d blocks of 0x%08lx bytes each", &num_blocks, &device_size);
	if ((!num_blocks) || (!device_size))
		goto out;

	if (num_blocks * device_size != 0x800000)
		goto out;

#if defined(DEBUG)
	fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: flash size of 8 MB was detected ...\n",
		node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
		node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
		node->router_type->desc);
#endif

	ret = 1;

out:
	return ret;
}

#if defined(DEBUG)
static int redboot_4mb_detect(struct node *node)
#else
static int redboot_4mb_detect(struct node (*node)__attribute__((unused)))
#endif
{
	/* default redboot type */
#if defined(DEBUG)
	fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: flash size of 4 MB was detected (default) ...\n",
		node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
		node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
		node->router_type->desc);
#endif
	return 1;
}

static struct redboot_type redboot_8mb = {
	.flash_size = 0x7A0000,
	.freememlo = 0x80041000, /* %{FREEMEMLO} provokes errors on the meraki mini */
	.flash_addr = 0xa8030000,
	.kernel_load_addr = 0x80041000,
	.detect = redboot_8mb_detect,
};

static struct redboot_type redboot_4mb = {
	.flash_size = 0x3A0000,
	.freememlo = 0, /* we can use %{FREEMEMLO} */
	.flash_addr = 0xbfc30000,
	.kernel_load_addr = 0x80041000,
	.detect = redboot_4mb_detect,
};

const struct redboot_type *redboot_types[] = {
	&redboot_8mb,
	&redboot_4mb,
	NULL,
};

int redboot_type_detect(struct node *node)
{
	struct redboot_priv *redboot_priv = node->router_priv;
	const struct redboot_type **redboot_type;
	int ret = 0;

	for (redboot_type = redboot_types; *redboot_type; ++redboot_type) {
		if (!(*redboot_type)->detect)
			continue;

		ret = (*redboot_type)->detect(node);
		if (ret != 1)
			continue;

		redboot_priv->redboot_type = (struct redboot_type *)(*redboot_type);
		break;
	}

	return ret;
}

void redboot_main(struct node *node, char *telnet_msg)
{
	struct redboot_priv *redboot_priv = node->router_priv;
	struct file_info *file_info;
	unsigned long req_flash_size;
	char buff[100];

	switch (redboot_priv->redboot_state) {
	case REDBOOT_STATE_INIT:
		redboot_priv->redboot_state = REDBOOT_STATE_VERSION;
		telnet_send_cmd(node, "version\n");
		break;
	case REDBOOT_STATE_VERSION:
		redboot_priv->version_info = malloc(strlen(telnet_msg) + 1);
		if (!redboot_priv->version_info)
			goto redboot_failure;

		strcpy(redboot_priv->version_info, telnet_msg);
		redboot_type_detect(node);

		req_flash_size = ((node->router_type->image->file_size + FLASH_PAGE_SIZE - 1) /
							FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE;

		if (redboot_priv->redboot_type->flash_size < req_flash_size) {
			fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: image size '%s' of 0x%08lx exceeds router capacity: 0x%08lx\n",
				node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
				node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
				node->router_type->desc, node->router_type->image->path,
				req_flash_size, redboot_priv->redboot_type->flash_size);
			goto redboot_failure;
		}

		sprintf(buff, "ip_addr -l %d.%d.%d.%d/8 -h %d.%d.%d.%d\n",
			((unsigned char *)&node->his_ip_addr)[0], ((unsigned char *)&node->his_ip_addr)[1],
			((unsigned char *)&node->his_ip_addr)[2], ((unsigned char *)&node->his_ip_addr)[3],
			((unsigned char *)&node->our_ip_addr)[0], ((unsigned char *)&node->our_ip_addr)[1],
			((unsigned char *)&node->our_ip_addr)[2], ((unsigned char *)&node->our_ip_addr)[3]);

		printf("[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: setting IP address ...\n",
		       node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
		       node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
		       node->router_type->desc);

		telnet_send_cmd(node, buff);
		redboot_priv->redboot_state = REDBOOT_STATE_IP_ADDR;
		break;
	case REDBOOT_STATE_IP_ADDR:
		if (redboot_priv->redboot_type->freememlo)
			sprintf(buff, "load -r -b 0x%08lx -m tftp kernel\n",
				redboot_priv->redboot_type->freememlo);
		else
			sprintf(buff, "load -r -b %%{FREEMEMLO} -m tftp kernel\n");

		telnet_send_cmd(node, buff);
		redboot_priv->redboot_state = REDBOOT_STATE_LD_KERNEL;
		break;
	case REDBOOT_STATE_LD_KERNEL:
		if ((unsigned int)node->image_state.bytes_sent < node->image_state.flash_size) {
			fprintf(stderr, "Error transferring kernel, send: %d, expected: %d\n",
				node->image_state.bytes_sent, node->image_state.flash_size);
			goto redboot_failure;
		}

		printf("[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: initializing partitions ...\n",
		       node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
		       node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
		       node->router_type->desc);

		telnet_send_cmd(node, "fis init\n");
		redboot_priv->redboot_state = REDBOOT_STATE_FIS_INIT;
		break;
	case REDBOOT_STATE_FIS_INIT:
		telnet_send_cmd(node, "y\n");
		redboot_priv->redboot_state = REDBOOT_STATE_FIS_INITY;
		break;
	case REDBOOT_STATE_FIS_INITY:
		sprintf(buff, "fis create -e 0x%08lx -r 0x%08lx vmlinux.bin.l7\n",
			redboot_priv->redboot_type->kernel_load_addr,
			redboot_priv->redboot_type->kernel_load_addr);

		printf("[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: flashing kernel ...\n",
		       node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
		       node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
		       node->router_type->desc);

		telnet_send_cmd(node, buff);
		redboot_priv->redboot_state = REDBOOT_STATE_FL_KERNEL;
		break;
	case REDBOOT_STATE_FL_KERNEL:
		if (redboot_priv->redboot_type->freememlo)
			sprintf(buff, "load -r -b 0x%08lx -m tftp rootfs\n",
				redboot_priv->redboot_type->freememlo);
		else
			sprintf(buff, "load -r -b %%{FREEMEMLO} -m tftp rootfs\n");

		telnet_send_cmd(node, buff);
		redboot_priv->redboot_state = REDBOOT_STATE_LD_ROOTFS;
		break;
	case REDBOOT_STATE_LD_ROOTFS:
		file_info = router_image_get_file(node->router_type, "kernel");
		if (!file_info)
			return;

		sprintf(buff, "fis create -f 0x%08lx -l 0x%08lx rootfs\n",
			redboot_priv->redboot_type->flash_addr + file_info->file_fsize,
			redboot_priv->redboot_type->flash_size - file_info->file_fsize);

		printf("[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: flashing rootfs ...\n",
		       node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
		       node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
		       node->router_type->desc);

		telnet_send_cmd(node, buff);
		redboot_priv->redboot_state = REDBOOT_STATE_FL_ROOTFS;
		break;
	case REDBOOT_STATE_FL_ROOTFS:
		printf("[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: setting boot_script_data ...\n",
		       node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
		       node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
		       node->router_type->desc);

		telnet_send_cmd(node, "fconfig -d boot_script_data\n");
		redboot_priv->redboot_state = REDBOOT_STATE_BSCRIPT;
		break;
	case REDBOOT_STATE_BSCRIPT:
		telnet_send_cmd(node, "fis load -l vmlinux.bin.l7\n");
		redboot_priv->redboot_state = REDBOOT_STATE_BSCRIPTK;
		break;
	case REDBOOT_STATE_BSCRIPTK:
		telnet_send_cmd(node, "exec\n\n");
		redboot_priv->redboot_state = REDBOOT_STATE_EXEC;
		break;
	case REDBOOT_STATE_EXEC:
		telnet_send_cmd(node, "y\n");
		redboot_priv->redboot_state = REDBOOT_STATE_EXECY;
		break;
	case REDBOOT_STATE_EXECY:
		telnet_send_cmd(node, "reset\n");
		redboot_priv->redboot_state = REDBOOT_STATE_FINISHED;
		node->status = NODE_STATUS_RESET_SENT;
		break;
	default:
		break;
	}

	return;

redboot_failure:
	redboot_priv->redboot_state = REDBOOT_STATE_FAILED;
	// TODO: close telnet connection ?
	return;
}

static int redboot_detect_main(void *priv, char *packet_buff, int packet_buff_len)
{
	struct ether_arp *arphdr;
	struct redboot_priv *redboot_priv = priv;
	int ret = 0;

	if (!len_check(packet_buff_len, sizeof(struct ether_arp), "ARP"))
		goto out;

	arphdr = (struct ether_arp *)packet_buff;
	if (arphdr->ea_hdr.ar_op != htons(ARPOP_REQUEST))
		goto out;

	/* we are waiting for gratuitous ARP requests */
	if (*((unsigned int *)arphdr->arp_spa) != *((unsigned int *)arphdr->arp_tpa))
		goto out;

	/**
	 * use gratuitous ARP requests from ubnt devices with care
	 * the ubnt pico can be in redboot or tftp server mode
	 */
	if (*((unsigned int *)arphdr->arp_spa) == htonl(ubnt_ip)) {
		if (redboot_priv->arp_count < 5) {
			redboot_priv->arp_count++;
			goto out;
		}
	}

	/* printf("redboot_detect_main(): receiving packet: len: %i (arp: %i, arp_count: %i)\n",
	       packet_buff_len, sizeof(struct ether_arp), redboot_priv->arp_count);*/

	ret = 1;

out:
	return ret;
}

static void redboot_detect_post(struct node *node, char *packet_buff, int packet_buff_len)
{
	struct ether_arp *arphdr;

	if (!len_check(packet_buff_len, sizeof(struct ether_arp), "ARP"))
		goto out;

	arphdr = (struct ether_arp *)packet_buff;

	if (arphdr->arp_tpa[3] == 20)
		arphdr->arp_tpa[3] = 1;
	else
		arphdr->arp_tpa[3] = 20;

	node->flash_mode = FLASH_MODE_REDBOOT;
	node->his_ip_addr = *((unsigned int *)(arphdr->arp_spa));
	node->our_ip_addr = *((unsigned int *)(arphdr->arp_tpa));

out:
	return;
}

const struct router_type redboot = {
	.desc = "redboot",
	.detect_pre = NULL,
	.detect_main = redboot_detect_main,
	.detect_post = redboot_detect_post,
	.image = &img_ci,
	.priv_size = sizeof(struct redboot_priv),
};
