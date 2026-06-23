// SPDX-License-Identifier: GPL-3.0-or-later
/* SPDX-FileCopyrightText: Marek Lindner <marek.lindner@mailbox.org>
 */

#include "router_redboot.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "ap51-flash.h"
#include "compat.h"
#include "flash.h"
#include "proto.h"
#include "router_images.h"
#include "router_types.h"

enum redboot_state {
	REDBOOT_STATE_INIT,
	REDBOOT_STATE_VERSION,
	REDBOOT_STATE_IP_ADDR,
	REDBOOT_STATE_LD_KERNEL,
	REDBOOT_STATE_FL_KERNEL,
	REDBOOT_STATE_LD_ROOTFS,
	REDBOOT_STATE_FL_ROOTFS,
	REDBOOT_STATE_BSCRIPT,
	REDBOOT_STATE_BSCRIPTK,
	REDBOOT_STATE_EXEC,
	REDBOOT_STATE_EXECY,
	REDBOOT_STATE_RESET,
	REDBOOT_STATE_FINISHED,
	REDBOOT_STATE_FIS_INIT,
	REDBOOT_STATE_FIS_INITY,
	REDBOOT_STATE_FAILED,
};

static const unsigned int ubnt_ip = 3232235796UL; /* 192.168.1.20 */

struct redboot_priv {
	int arp_count;
	enum redboot_state redboot_state;
	struct redboot_type *redboot_type;
};

#if defined(DEBUG)
static int redboot_8mb_detect(struct node *node, const char *version_info)
#else
static int redboot_8mb_detect(struct node (*node)__attribute__((unused)),
			      const char *version_info)
#endif
{
	unsigned long device_size = 0;
	char *flash_str;
	int num_blocks = 0, ret = 0;

	flash_str = strstr(version_info, "FLASH:");
	if (!flash_str)
		goto out;

	sscanf(flash_str,
	       "FLASH: 0x%*08x - 0x%*08x, %d blocks of 0x%08lx bytes each",
	       &num_blocks, &device_size);
	if ((!num_blocks) || (!device_size))
		goto out;

	if (num_blocks * device_size != 0x800000)
		goto out;

#if defined(DEBUG)
	fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s: flash size of 8 MB was detected ...\n",
		node->his_mac_addr[0], node->his_mac_addr[1],
		node->his_mac_addr[2], node->his_mac_addr[3],
		node->his_mac_addr[4], node->his_mac_addr[5],
		node->router_type->desc);
#endif

	ret = 1;

out:
	return ret;
}

#if defined(DEBUG)
static int redboot_4mb_detect(struct node *node,
			      const char *version_info __attribute__((unused)))
#else
static int redboot_4mb_detect(struct node (*node)__attribute__((unused)),
			      const char *version_info __attribute__((unused)))
#endif
{
	/* default redboot type */
#if defined(DEBUG)
	fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s: flash size of 4 MB was detected (default) ...\n",
		node->his_mac_addr[0], node->his_mac_addr[1],
		node->his_mac_addr[2], node->his_mac_addr[3],
		node->his_mac_addr[4], node->his_mac_addr[5],
		node->router_type->desc);
#endif
	return 1;
}

static const struct redboot_type redboot_8mb = {
	.flash_size = 0x7A0000,
	.freememlo = 0x80041000, /* %{FREEMEMLO} provokes errors on the meraki mini */
	.flash_addr = 0xa8030000,
	.kernel_load_addr = 0x80041000,
	.detect = redboot_8mb_detect,
};

static const struct redboot_type redboot_4mb = {
	.flash_size = 0x3A0000,
	.freememlo = 0, /* we can use %{FREEMEMLO} */
	.flash_addr = 0xbfc30000,
	.kernel_load_addr = 0x80041000,
	.detect = redboot_4mb_detect,
};

static const struct redboot_type *redboot_types[] = {
	&redboot_8mb,
	&redboot_4mb,
	NULL,
};

static int redboot_type_detect(struct node *node, const char *version_info)
{
	struct redboot_priv *redboot_priv = node->router_priv;
	const struct redboot_type **redboot_type;
	int ret = 0;

	for (redboot_type = redboot_types; *redboot_type; ++redboot_type) {
		if (!(*redboot_type)->detect)
			continue;

		ret = (*redboot_type)->detect(node, version_info);
		if (ret != 1)
			continue;

		redboot_priv->redboot_type = (struct redboot_type *)(*redboot_type);
		break;
	}

	return ret;
}

/* ask RedBoot to load a file from our TFTP server into RAM. The transfer
 * state is only refreshed when RedBoot's read request is served, so forget
 * the previous transfer first: a load without a read request must not pass
 * redboot_transfer_done() with the values of the previous file
 */
static void redboot_load(struct node *node, const char *name)
{
	struct redboot_priv *redboot_priv = node->router_priv;
	char buff[100];

	if (redboot_priv->redboot_type->freememlo)
		sprintf(buff, "load -r -b 0x%08lx -m tftp %s\n",
			redboot_priv->redboot_type->freememlo, name);
	else
		sprintf(buff, "load -r -b %%{FREEMEMLO} -m tftp %s\n", name);

	node->image_state.file_requested = 0;
	node->image_state.bytes_sent = 0;
	node->image_state.flash_size = 1;
	telnet_send_cmd(node, buff);
}

/* RedBoot's messages that end a load command */
static const char * const redboot_load_results[] = {
	"Raw file loaded",
	"Can't load",
	"Unable to reach host",
	"*** Abort",
	NULL,
};

static bool redboot_load_ended(const char *telnet_msg)
{
	const char * const *result;

	for (result = redboot_load_results; *result; result++) {
		if (strstr(telnet_msg, *result))
			return true;
	}

	return false;
}

/* check the transfer started by redboot_load() after RedBoot sent telnet_msg.
 * Returns 1 when the file was transferred, 0 when the load is still running
 * and -1 when it failed
 */
static int redboot_transfer_done(struct node *node, const char *name,
				 const char *telnet_msg)
{
	/* RedBoot didn't ask for the file yet. Unless the load already ended
	 * (e.g. RedBoot could not reach us), the message is the remainder of
	 * the output of the previous command (split into several segments)
	 */
	if (!node->image_state.file_requested &&
	    !redboot_load_ended(telnet_msg))
		return 0;

	if (node->image_state.bytes_sent >= node->image_state.flash_size)
		return 1;

	fprintf(stderr, "Error transferring %s, send: %u, expected: %u\n",
		name, node->image_state.bytes_sent,
		node->image_state.flash_size);
	return -1;
}

void redboot_main(struct node *node, const char *telnet_msg)
{
	struct redboot_priv *redboot_priv = node->router_priv;
	struct file_info *file_info;
	unsigned long req_flash_size;
	char buff[100];
	int ret;

	switch (redboot_priv->redboot_state) {
	case REDBOOT_STATE_INIT:
		redboot_priv->redboot_state = REDBOOT_STATE_VERSION;
		telnet_send_cmd(node, "version\n");
		break;
	case REDBOOT_STATE_VERSION:
		redboot_type_detect(node, telnet_msg);

		req_flash_size = ((node->router_type->image->file_size + FLASH_PAGE_SIZE - 1) /
							FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE;

		if (redboot_priv->redboot_type->flash_size < req_flash_size) {
			fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s: image size '%s' of 0x%08lx exceeds device capacity: 0x%08lx\n",
				node->his_mac_addr[0], node->his_mac_addr[1],
				node->his_mac_addr[2], node->his_mac_addr[3],
				node->his_mac_addr[4], node->his_mac_addr[5],
				node->router_type->desc, node->router_type->image->path,
				req_flash_size, redboot_priv->redboot_type->flash_size);
			goto redboot_failure;
		}

		sprintf(buff, "ip_addr -l %d.%d.%d.%d/8 -h %d.%d.%d.%d\n",
			((unsigned char *)&node->his_ip_addr)[0], ((unsigned char *)&node->his_ip_addr)[1],
			((unsigned char *)&node->his_ip_addr)[2], ((unsigned char *)&node->his_ip_addr)[3],
			((unsigned char *)&node->our_ip_addr)[0], ((unsigned char *)&node->our_ip_addr)[1],
			((unsigned char *)&node->our_ip_addr)[2], ((unsigned char *)&node->our_ip_addr)[3]);

		printf("[%02x:%02x:%02x:%02x:%02x:%02x]: %s: setting IP address ...\n",
		       node->his_mac_addr[0], node->his_mac_addr[1],
		       node->his_mac_addr[2], node->his_mac_addr[3],
		       node->his_mac_addr[4], node->his_mac_addr[5],
		       node->router_type->desc);

		telnet_send_cmd(node, buff);
		redboot_priv->redboot_state = REDBOOT_STATE_IP_ADDR;
		break;
	case REDBOOT_STATE_IP_ADDR:
		redboot_load(node, "kernel");
		redboot_priv->redboot_state = REDBOOT_STATE_LD_KERNEL;
		break;
	case REDBOOT_STATE_LD_KERNEL:
		ret = redboot_transfer_done(node, "kernel", telnet_msg);
		if (ret == 0) {
			/* nothing to answer; keep RedBoot from retransmitting
			 * the output (which would resend the load command)
			 */
			telnet_send_ack(node);
			break;
		}

		if (ret < 0)
			goto redboot_failure;

		printf("[%02x:%02x:%02x:%02x:%02x:%02x]: %s: initializing partitions ...\n",
		       node->his_mac_addr[0], node->his_mac_addr[1],
		       node->his_mac_addr[2], node->his_mac_addr[3],
		       node->his_mac_addr[4], node->his_mac_addr[5],
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

		printf("[%02x:%02x:%02x:%02x:%02x:%02x]: %s: flashing kernel ...\n",
		       node->his_mac_addr[0], node->his_mac_addr[1],
		       node->his_mac_addr[2], node->his_mac_addr[3],
		       node->his_mac_addr[4], node->his_mac_addr[5],
		       node->router_type->desc);

		telnet_send_cmd(node, buff);
		redboot_priv->redboot_state = REDBOOT_STATE_FL_KERNEL;
		break;
	case REDBOOT_STATE_FL_KERNEL:
		redboot_load(node, "rootfs");
		redboot_priv->redboot_state = REDBOOT_STATE_LD_ROOTFS;
		break;
	case REDBOOT_STATE_LD_ROOTFS:
		ret = redboot_transfer_done(node, "rootfs", telnet_msg);
		if (ret == 0) {
			/* nothing to answer; keep RedBoot from retransmitting
			 * the output (which would resend the load command)
			 */
			telnet_send_ack(node);
			break;
		}

		if (ret < 0)
			goto redboot_failure;

		file_info = router_image_get_file(node->router_type, "kernel");
		if (!file_info)
			return;

		sprintf(buff, "fis create -f 0x%08lx -l 0x%08lx rootfs\n",
			redboot_priv->redboot_type->flash_addr + file_info->file_fsize,
			redboot_priv->redboot_type->flash_size - file_info->file_fsize);

		printf("[%02x:%02x:%02x:%02x:%02x:%02x]: %s: flashing rootfs ...\n",
		       node->his_mac_addr[0], node->his_mac_addr[1],
		       node->his_mac_addr[2], node->his_mac_addr[3],
		       node->his_mac_addr[4], node->his_mac_addr[5],
		       node->router_type->desc);

		telnet_send_cmd(node, buff);
		redboot_priv->redboot_state = REDBOOT_STATE_FL_ROOTFS;
		break;
	case REDBOOT_STATE_FL_ROOTFS:
		printf("[%02x:%02x:%02x:%02x:%02x:%02x]: %s: setting boot_script_data ...\n",
		       node->his_mac_addr[0], node->his_mac_addr[1],
		       node->his_mac_addr[2], node->his_mac_addr[3],
		       node->his_mac_addr[4], node->his_mac_addr[5],
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

static int redboot_detect_main(const struct router_type *router_type __attribute__((unused)),
			       void *priv, const char *packet_buff,
			       int packet_buff_len)
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
	if (load_ip_addr(arphdr->arp_spa) != load_ip_addr(arphdr->arp_tpa))
		goto out;

	/**
	 * use gratuitous ARP requests from ubnt devices with care
	 * the ubnt pico can be in redboot or tftp server mode
	 */
	if (load_ip_addr(arphdr->arp_spa) == htonl(ubnt_ip)) {
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

static void redboot_detect_post(struct node *node, const char *packet_buff,
				int packet_buff_len)
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
	node->his_ip_addr = load_ip_addr(arphdr->arp_spa);
	node->our_ip_addr = load_ip_addr(arphdr->arp_tpa);

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
