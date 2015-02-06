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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "types.h"
#include "proto.h"
#include "flash.h"
#include "socket.h"
#include "router_types.h"
#include "router_images.h"
#include "router_redboot.h"
#include "router_tftp_client.h"

#define TFTP_SRC_PORT 13337
#define REDBOOT_TELNET_SPORT 13337
#define REDBOOT_TELNET_DPORT 9000

#define TFTP_PAYLOAD_SIZE 512

#define TCP_SYN 0x01
#define TCP_ACK 0x02
#define TCP_DATA 0x03

#define PACKET_BUFF_LEN 2000
#define ARP_LEN (sizeof(struct ether_header) + sizeof(struct ether_arp))
#define MAX_TCP_PAYLOAD (ETH_DATA_LEN - ETH_HLEN - sizeof(struct iphdr) - sizeof(struct tcphdr))

static char *out_packet_buff;
static struct ether_header *out_ethhdr;
static struct ether_arp *out_arphdr;
static struct iphdr *out_iphdr;
static struct udphdr *out_udphdr;
static char *out_tftp_data;

static void arp_init(uint8_t *src_mac, uint8_t *dst_mac, unsigned int src_ip, unsigned int dst_ip, unsigned short arp_type)
{
	memcpy(out_ethhdr->ether_shost, src_mac, ETH_ALEN);
	memcpy(out_ethhdr->ether_dhost, dst_mac, ETH_ALEN);
	out_ethhdr->ether_type = htons(ETH_P_ARP);

	out_arphdr->ea_hdr.ar_hrd = htons(0x0001); /* ethernet */
	out_arphdr->ea_hdr.ar_pro = htons(ETH_P_IP); /* IPv4 */
	out_arphdr->ea_hdr.ar_hln = ETH_ALEN;
	out_arphdr->ea_hdr.ar_pln = 4; /* IPv4 addr len */

	out_arphdr->ea_hdr.ar_op = htons(arp_type);
	memcpy(out_arphdr->arp_sha, src_mac, ETH_ALEN);
	*((unsigned int *)out_arphdr->arp_spa) = src_ip;
	*((unsigned int *)out_arphdr->arp_tpa) = dst_ip;
}

int arp_req_send(uint8_t *src_mac, uint8_t *dst_mac, unsigned int src_ip, unsigned int dst_ip)
{
	arp_init(src_mac, dst_mac, src_ip, dst_ip, ARPOP_REQUEST);

	return socket_write(out_packet_buff, ARP_LEN);
}

static int arp_rep_send(uint8_t *src_mac, uint8_t *dst_mac, unsigned int src_ip, unsigned int dst_ip)
{
	arp_init(src_mac, dst_mac, src_ip, dst_ip, ARPOP_REPLY);

	/* fprintf(stderr, "arp_rep_send() to: %02x:%02x:%02x:%02x:%02x:%02x from %02x:%02x:%02x:%02x:%02x:%02x\n",
			dst_mac[0], dst_mac[1], dst_mac[2],
			dst_mac[3], dst_mac[4], dst_mac[5],
			src_mac[0], src_mac[1], src_mac[2],
			src_mac[3], src_mac[4], src_mac[5]);*/

	return socket_write(out_packet_buff, ARP_LEN);
}

static void tftp_packet_init(struct node *node, unsigned short src_port, unsigned short dst_port)
{
	memcpy(out_ethhdr->ether_shost, node->our_mac_addr, ETH_ALEN);
	memcpy(out_ethhdr->ether_dhost, node->his_mac_addr, ETH_ALEN);
	out_ethhdr->ether_type = htons(ETH_P_IP);

	out_iphdr->version = 4;
	out_iphdr->ihl = 5;
	out_iphdr->tos = 0;
	out_iphdr->id = 0;
	out_iphdr->frag_off = 0;
	out_iphdr->ttl = 50;
	out_iphdr->protocol = IPPROTO_UDP;
	out_iphdr->saddr = node->our_ip_addr;
	out_iphdr->daddr = node->his_ip_addr;

	out_udphdr->source = src_port;
	out_udphdr->dest = dst_port;
}

static int tftp_packet_send_data(struct node *node, unsigned short src_port,
				 unsigned short dst_port, int tftp_data_len)
{
	unsigned short sum;

	tftp_packet_init(node, src_port, dst_port);
	out_udphdr->len = htons(8 + tftp_data_len);

	/* UDP checksum */
	out_udphdr->check = 0;
	sum = ntohs(out_udphdr->len) + out_iphdr->protocol;
	sum = chksum(sum, (void *)&out_iphdr->saddr, 2 * sizeof(out_iphdr->saddr));
	sum = chksum(sum, (void *)out_udphdr, ntohs(out_udphdr->len));
	out_udphdr->check = ~(htons(sum));

	out_iphdr->tot_len = htons(20 + 8 + tftp_data_len);
	out_iphdr->check = 0;
	out_iphdr->check = ~(htons(chksum(0, (void *)out_iphdr, sizeof(struct iphdr))));

	return socket_write(out_packet_buff, ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + tftp_data_len);
}

int tftp_init_upload(struct node *node)
{
	int data_len;

	/* TFTP write request */
	*((unsigned short *)out_tftp_data) = htons(2);
	data_len = 2;
	data_len += sprintf(out_tftp_data + data_len, "\"%s\"", "flash_update");
	data_len += sprintf(out_tftp_data + data_len + 1, "%s", "octet");
	data_len += 2; /* sprintf does not count \0 */

	return tftp_packet_send_data(node, htons(TFTP_SRC_PORT), htons(IPPORT_TFTP), data_len);
}

static void handle_arp_packet(char *packet_buff, int packet_buff_len, struct node *node)
{
	struct ether_arp *arphdr;
	int ret;

	if (!len_check(packet_buff_len, sizeof(struct ether_arp), "ARP"))
		return;

	arphdr = (struct ether_arp *)packet_buff;

	switch (ntohs(arphdr->ea_hdr.ar_op)) {
	case ARPOP_REQUEST:
		/* fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: received ARP request, status: %d\n",
			node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
			node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
			node->status); */
		break;
	case ARPOP_REPLY:
		/* fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: received ARP reply, status: %d\n",
			node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
			node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
			node->status); */
		break;
	default:
		/* fprintf(stderr, "ARP, unknown op code: %i, status: %d\n", ntohs(arphdr->ea_hdr.ar_op), node->status); */
		return;
	}

	switch (node->status) {
	case NODE_STATUS_UNKNOWN:
		node->status = NODE_STATUS_DETECTING;
		/* fall through */
	case NODE_STATUS_DETECTING:
		ret = router_types_detect_main(node, packet_buff, packet_buff_len);
		if (ret == 1)
			node->status = NODE_STATUS_DETECTED;
		else
			break;
	case NODE_STATUS_DETECTED:
	case NODE_STATUS_FLASHING:
		if (ntohs(arphdr->ea_hdr.ar_op) != ARPOP_REQUEST)
			break;

		arp_rep_send(node->our_mac_addr, node->his_mac_addr,
			     node->our_ip_addr, node->his_ip_addr);
		break;
	case NODE_STATUS_RESET_SENT:
	case NODE_STATUS_FINISHED:
		fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: flash complete. Device ready to unplug.\n",
			node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
			node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
			node->router_type->desc);
		node->status = NODE_STATUS_REBOOTED;
#if defined(CLEAR_SCREEN)
		num_nodes_flashed++;
#endif
		break;
	case NODE_STATUS_REBOOTED:
	case NODE_STATUS_NO_FLASH:
		break;
	}
}

static void handle_udp_packet(char *packet_buff, int packet_buff_len, struct node *node)
{
	struct udphdr *udphdr;
	struct file_info *file_info;
	unsigned short opcode, block;
	char *file_name;
	int ret, data_len;

	if (!len_check(packet_buff_len, sizeof(struct udphdr), "UDP"))
		return;

	udphdr = (struct udphdr *)packet_buff;

	switch (node->flash_mode) {
	case FLASH_MODE_REDBOOT:
	case FLASH_MODE_TFTP_CLIENT:
		if (udphdr->dest != htons(IPPORT_TFTP))
			return;

		break;
	case FLASH_MODE_TFTP_SERVER:
		if (udphdr->source != htons(IPPORT_TFTP))
			return;

		break;
	default:
		return;
	}

	opcode = ntohs(*(unsigned short *)(packet_buff + sizeof(struct udphdr)));
	block = ntohs(*(unsigned short *)(packet_buff + sizeof(struct udphdr) + 2));
	/* fprintf(stderr, "tftp opcode=%d, block=%d, len=%i\n", opcode,
		block, htons(rcv_udphdr->len) - sizeof(struct udphdr)); */

	switch (opcode) {
	/* TFTP read request */
	case 1:
		file_name = packet_buff + sizeof(struct udphdr) + 2;
		switch (node->flash_mode) {
		case FLASH_MODE_REDBOOT:
		case FLASH_MODE_TFTP_CLIENT:
			file_info = router_image_get_file(node->router_type, file_name);
			if (!file_info) {
				fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: tftp client asks for '%s' - file not found ...\n",
					node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
					node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
					node->router_type->desc, file_name);
				goto out;
			}

			if (node->image_state.fd <= 0) {
				ret = router_images_open_path(node);
				if (ret < 0)
					goto out;
				node->status = NODE_STATUS_FLASHING;
			}

			fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: tftp client asks for '%s', serving %s portion of: %s (%i blocks) ...\n",
				node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
				node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
				node->router_type->desc, file_name,file_info->file_name,
				node->router_type->image->path ? node->router_type->image->path : "embedded image",
				((file_info->file_fsize + TFTP_PAYLOAD_SIZE - 1) / TFTP_PAYLOAD_SIZE));

			node->image_state.file_size = file_info->file_size;
			node->image_state.flash_size = file_info->file_fsize;
			node->image_state.offset = file_info->file_offset;
			break;
		}

		block = 0;
		node->image_state.bytes_sent = 0;
		node->image_state.last_packet_size = 0;
		/* fall through - start sending data */
	/* TFTP ack */
	case 4:
		if (block == 0) {
			if (node->flash_mode == FLASH_MODE_TFTP_SERVER) {
				ret = router_images_open_path(node);
				if (ret < 0)
					return;
				node->status = NODE_STATUS_FLASHING;
				node->image_state.file_size = node->router_type->image->file_size;
				node->image_state.flash_size = ((node->router_type->image->file_size + FLASH_PAGE_SIZE - 1) /
										FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE;
				node->image_state.offset = 0;

				fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: connection to tftp server established - uploading %i blocks ...\n",
					node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
					node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
					node->router_type->desc,
					((node->image_state.flash_size + TFTP_PAYLOAD_SIZE - 1) / TFTP_PAYLOAD_SIZE));
			}

			node->image_state.block_acked = 0;
			node->image_state.block_sent = 0;
		} else if (block != node->image_state.block_sent) {
			if (block < node->image_state.block_sent)
				fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: tftp repeat block %d, last received ack: %d\n",
					node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
					node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
					node->router_type->desc, block + 1, node->image_state.block_acked);
			else
				fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: tftp acks unsent block %d (last sent block: %d)\n",
					node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
					node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
					node->router_type->desc, block, node->image_state.block_sent);

			block = node->image_state.block_acked;
			node->image_state.bytes_sent -= node->image_state.last_packet_size;
		} else {
			/* nothing more to send */
			if (node->image_state.last_packet_size != TFTP_PAYLOAD_SIZE) {
				node->image_state.total_bytes_sent += node->image_state.bytes_sent;

				if (node->image_state.total_bytes_sent >= node->router_type->image->file_size) {
					switch (node->flash_mode) {
					case FLASH_MODE_TFTP_SERVER:
					case FLASH_MODE_TFTP_CLIENT:
						fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: image successfully transmitted - writing image to flash ...\n",
							node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
							node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
							node->router_type->desc);
						router_images_close_path(node);
						if (node->flash_mode == FLASH_MODE_TFTP_CLIENT)
							tftp_client_flash_time_set(node);
						node->status = NODE_STATUS_FINISHED;
						break;
					}
				}

				goto out;
			}

			node->image_state.block_acked = block;
		}

		block++;

		/* TFTP DATA packet */
		*((unsigned short *)out_tftp_data) = htons(3);
		*((unsigned short *)(out_tftp_data + 2)) = htons(block);

		data_len = router_images_read_data(out_tftp_data + 4, node);
		if (data_len < 0)
			break;

		data_len += 4; /* opcode size */

		ret = tftp_packet_send_data(node, udphdr->dest, udphdr->source, data_len);
		if (ret < 0)
			return;

		node->image_state.last_packet_size = data_len - 4; /* opcode size */
		node->image_state.bytes_sent += node->image_state.last_packet_size;
		node->image_state.block_sent = block;
		/* printf("tftp data out: tftp_sent=%lu, remaining_size=%lu, data_len=%i, block=%d\n",
			tftp_sent, tftp_xfer_size - tftp_sent, tftp_data_len - 4, block); */
		break;
	/* TFTP error */
	case 5:
		if ((block == 2) && (htons(udphdr->len) - sizeof(struct udphdr) > 4))
			fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: received TFTP error: %s\n",
				node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
				node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
				node->router_type->desc, (packet_buff + sizeof(struct udphdr) + 4));
		else
			fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: received TFTP error code: %d\n",
				node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
				node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
				node->router_type->desc, block);

		break;
	default:
		fprintf(stderr, "[%02x:%02x:%02x:%02x:%02x:%02x]: %s router: unexpected TFTP opcode: %d\n",
			node->his_mac_addr[0], node->his_mac_addr[1], node->his_mac_addr[2],
			node->his_mac_addr[3], node->his_mac_addr[4], node->his_mac_addr[5],
			node->router_type->desc, opcode);
		break;
	}

out:
	return;
}

void tcp_init_state(struct node *node)
{
	struct ether_header *ethhdr;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;

	node->tcp_state.packet_buff = malloc(PACKET_BUFF_LEN);
	if (!node->tcp_state.packet_buff)
		goto out;

	memset(node->tcp_state.packet_buff, 0, PACKET_BUFF_LEN);

	ethhdr = (struct ether_header *)node->tcp_state.packet_buff;
	memcpy(ethhdr->ether_shost, node->our_mac_addr, ETH_ALEN);
	memcpy(ethhdr->ether_dhost, node->his_mac_addr, ETH_ALEN);
	ethhdr->ether_type = htons(ETH_P_IP);

	iphdr = (struct iphdr *)(node->tcp_state.packet_buff + ETH_HLEN);
	iphdr->version = 4;
	iphdr->ihl = 5;
	iphdr->tos = 0;
	iphdr->id = 0;
	iphdr->frag_off = 0;
	iphdr->ttl = 50;
	iphdr->protocol = IPPROTO_TCP;
	iphdr->saddr = node->our_ip_addr;
	iphdr->daddr = node->his_ip_addr;

	tcphdr = (struct tcphdr *)(node->tcp_state.packet_buff + ETH_HLEN + sizeof(struct iphdr));
	tcphdr->source = htons(REDBOOT_TELNET_SPORT);
	tcphdr->dest = htons(REDBOOT_TELNET_DPORT);

out:
	return;
}

static int tcp_send(struct node *node, int tcp_data_len, int flags)
{
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;
	unsigned short sum;
	unsigned int mss_option = htonl(0x02040000 | MAX_TCP_PAYLOAD);

	iphdr = (struct iphdr *)(node->tcp_state.packet_buff + ETH_HLEN);
	tcphdr = (struct tcphdr *)(node->tcp_state.packet_buff + ETH_HLEN + sizeof(struct iphdr));

	/* tcp header */
	tcphdr->seq = htonl(node->tcp_state.my_seq);
	tcphdr->ack_seq = htonl(node->tcp_state.my_ack_seq);
	tcphdr->window = htons(MAX_TCP_PAYLOAD);
	tcphdr->doff = 5;

	/* always set PUSH flag if sending data */
	if (tcp_data_len > 0)
		tcphdr->psh = 1;
	else
		tcphdr->psh = 0;

	switch (flags) {
	case TCP_SYN:
		tcphdr->syn = 1;
		tcphdr->ack = 0;

		/* send MSS option */
		tcp_data_len += 4;
		memcpy((unsigned char *)(tcphdr + 1), &mss_option, sizeof(mss_option));
		tcphdr->doff++;
		break;
	case TCP_ACK:
	case TCP_DATA:
		tcphdr->syn = 0;
		tcphdr->ack = 1;
		break;
	}

	/* TCP checksum */
	tcphdr->check = 0;
	if (flags == TCP_SYN)
		sum = (tcphdr->doff * 4) + iphdr->protocol;
	else
		sum = (tcphdr->doff * 4) + tcp_data_len + iphdr->protocol;
	sum = chksum(sum, (void *)&iphdr->saddr, 2 * sizeof(iphdr->saddr));
	sum = chksum(sum, (void *)tcphdr, sizeof(struct tcphdr) + tcp_data_len);
	tcphdr->check = ~(htons(sum));

	iphdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + tcp_data_len);
	iphdr->check = 0;
	iphdr->check = ~(htons(chksum(0, (void *)iphdr, sizeof(struct iphdr))));

	return socket_write(node->tcp_state.packet_buff,
			    ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr) + tcp_data_len);
}

static int tcp_send_syn(struct node *node)
{
	return tcp_send(node, 0, TCP_SYN);
}

static int tcp_send_ack(struct node *node)
{
	return tcp_send(node, 0, TCP_ACK);
}

static int tcp_send_data(struct node *node, int tcp_data_len)
{
	return tcp_send(node, tcp_data_len, TCP_DATA);
}

static int tcp_resend_data(struct node *node)
{
	char *packet_buff;

	packet_buff = node->tcp_state.packet_buff + ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr);

	return tcp_send(node, (int)strlen(packet_buff), TCP_DATA);
}

void telnet_handle_connection(struct node *node)
{
	if (!node->tcp_state.packet_buff)
		tcp_init_state(node);

	if (!node->tcp_state.packet_buff)
		goto out;

	/* keep sending SYN packets until we get a reply */
	switch (node->tcp_state.status) {
	case TCP_STATUS_SYN_SENT:
		tcp_send_syn(node);
		break;
	case TCP_STATUS_ESTABLISHED:
		/* TODO: check timer if we need to resend */
		break;
	}

out:
	return;
}

int telnet_send_cmd(struct node *node, char *cmd)
{
	char *packet_buff;

	packet_buff = node->tcp_state.packet_buff + ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr);
	strcpy(packet_buff, cmd);
	return tcp_send_data(node, (int)strlen(cmd));
}

static void handle_tcp_packet(char *packet_buff, int packet_buff_len, struct node *node)
{
	struct tcphdr *tcphdr;
	unsigned int data_len;
	char *buff;

	if (!len_check(packet_buff_len, sizeof(struct tcphdr), "TCP"))
		goto out;

	tcphdr = (struct tcphdr *)packet_buff;

	/* not telnet */
	if (tcphdr->source != htons(REDBOOT_TELNET_DPORT))
		goto out;

	if (tcphdr->dest != htons(REDBOOT_TELNET_SPORT))
		goto out;

	if (tcphdr->ack != 1)
		goto out;

	data_len = packet_buff_len - (tcphdr->doff * 4);

	switch (node->tcp_state.status) {
	case TCP_STATUS_SYN_SENT:
		if (tcphdr->syn != 1)
			goto out;

		node->tcp_state.status = TCP_STATUS_ESTABLISHED;
		node->tcp_state.my_ack_seq = ntohl(tcphdr->seq) + 1;
		node->tcp_state.my_seq = ntohl(tcphdr->ack_seq);
		tcp_send_ack(node);
		break;
	case TCP_STATUS_ESTABLISHED:
		if (tcphdr->syn != 0)
			goto out;

		packet_buff[packet_buff_len - 1] = '\0';
		buff = (char *)(tcphdr + 1);
		node->tcp_state.status = TCP_STATUS_TELNET_READY;
		node->tcp_state.my_ack_seq += data_len;

		/* send CTRL + C */
		buff = node->tcp_state.packet_buff + ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr);
		buff[0] = 0x03;
		tcp_send_data(node, 1);
		break;
	case TCP_STATUS_TELNET_READY:
		if (tcphdr->syn != 0)
			goto out;

		/* check for retransmission */
		if ((tcphdr->seq == node->tcp_state.his_seq) &&
		    (tcphdr->ack_seq == node->tcp_state.his_ack_seq) &&
		    (data_len == node->tcp_state.his_last_len)) {
			/* printf("retransmission received: seq = %u, ack_seq: %u, len: %u\n",
			       ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq), data_len); */
			tcp_resend_data(node);
			goto out;
		}

		node->tcp_state.his_seq = tcphdr->seq;
		node->tcp_state.his_ack_seq = tcphdr->ack_seq;
		node->tcp_state.his_last_len = data_len;

		if (node->tcp_state.his_last_len == 0) {
			/* TODO probably should do something useful with the ACK */
			/* printf("received simple ACK (no text)\n"); */
			goto out;
		}

		node->tcp_state.my_ack_seq += data_len;
		if (ntohl(tcphdr->ack_seq) > node->tcp_state.my_seq)
			node->tcp_state.my_seq = ntohl(tcphdr->ack_seq);
		packet_buff[packet_buff_len] = '\0';
		redboot_main(node, (char *)(tcphdr + 1));
		break;
	default:
		return;
	}

out:
	return;
}

static void handle_ip_packet(char *packet_buff, int packet_buff_len, struct node *node)
{
	struct iphdr *iphdr;
	int length;

	if (!len_check(packet_buff_len, sizeof(struct iphdr), "IPv4"))
		return;

	iphdr = (struct iphdr *)packet_buff;
	if (!len_check(packet_buff_len, iphdr->ihl * 4, "IPv4 full"))
		return;

	switch (node->status) {
	case NODE_STATUS_DETECTED:
	case NODE_STATUS_FLASHING:
	case NODE_STATUS_RESET_SENT:
		break;
	case NODE_STATUS_UNKNOWN:
	case NODE_STATUS_DETECTING:
	case NODE_STATUS_FINISHED:
	case NODE_STATUS_NO_FLASH:
	default:
		return;
	}

	if (iphdr->saddr != node->his_ip_addr)
		return;

	if (iphdr->daddr != node->our_ip_addr)
		return;

	switch (iphdr->protocol) {
	case IPPROTO_UDP:
		handle_udp_packet(packet_buff + (iphdr->ihl * 4),
				  packet_buff_len - (iphdr->ihl * 4),
				  node);
		break;
	case IPPROTO_TCP:
		if (node->flash_mode != FLASH_MODE_REDBOOT)
			break;

		length = packet_buff_len;
		if (length > ntohs(iphdr->tot_len))
			length = ntohs(iphdr->tot_len);

		handle_tcp_packet(packet_buff + (iphdr->ihl * 4),
				  length - (iphdr->ihl * 4), node);
		break;
	}

	return;
}

void handle_eth_packet(char *packet_buff, int packet_buff_len)
{
	struct ether_header *eth_hdr;
	struct node *node;
	uint8_t bcast_addr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	if (!len_check(packet_buff_len, ETH_HLEN, "ethernet"))
		return;

	eth_hdr = (struct ether_header *)packet_buff;
	if (memcmp(eth_hdr->ether_shost, bcast_addr, ETH_ALEN) == 0)
		return;

	switch (ntohs(eth_hdr->ether_type)) {
	case ETH_P_ARP:
		node = node_list_get(eth_hdr->ether_shost);
		if (!node)
			return;
		handle_arp_packet(packet_buff + ETH_HLEN,
				  packet_buff_len - ETH_HLEN,
				  node);
		break;
	case ETH_P_IP:
		if (memcmp(eth_hdr->ether_dhost, bcast_addr, ETH_ALEN) == 0)
			return;

		node = node_list_get(eth_hdr->ether_shost);
		if (!node)
			return;

		handle_ip_packet(packet_buff + ETH_HLEN,
				 packet_buff_len - ETH_HLEN,
				 node);
		break;
	default:
		/* silently drop packet */
		break;
	}
}

int proto_init(void)
{
	int ret = -1;

	out_packet_buff = malloc(PACKET_BUFF_LEN);
	if (!out_packet_buff)
		goto out;

	out_ethhdr = (struct ether_header *)out_packet_buff;
	out_arphdr = (struct ether_arp *)(out_packet_buff + ETH_HLEN);
	out_iphdr = (struct iphdr *)(out_packet_buff + ETH_HLEN);
	out_udphdr = (struct udphdr *)(out_packet_buff + ETH_HLEN + sizeof(struct iphdr));
	out_tftp_data = (void *)(out_packet_buff + ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr));
	ret = 0;

out:
	return ret;
}

void proto_free(void)
{
	free(out_packet_buff);
}
