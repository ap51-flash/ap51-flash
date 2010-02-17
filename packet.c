/*
 * Copyright (C) Open Mesh, Inc., Marek Lindner
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
#include <string.h>

#include "packet.h"
#include "ap51-flash.h"
#include "socket.h"

#define PACKET_BUFF_LEN 1500

unsigned char packet_buff[PACKET_BUFF_LEN];
struct ether_header *ethhdr = (struct ether_header *)packet_buff;
struct ether_arp *arphdr = (struct ether_arp *)(packet_buff + sizeof(struct ether_header));
struct iphdr *iphdr = (struct iphdr *)(packet_buff + sizeof(struct ether_header));
struct udphdr *udphdr = (struct udphdr *)(packet_buff + sizeof(struct ether_header) + sizeof(struct iphdr));
void *tftp_data = (void *)(packet_buff + TFTP_BASE_LEN);

unsigned long tftp_bytes_sent = 0;
unsigned short tftp_ack_block = 0, tftp_sent_block = 0, xfer_in_progress = 0, write_req_timeout = 4;
char tcp_status = TCP_CONTINUE;


/* in uip.c */
u16_t chksum(u16_t sum, const u8_t *data, u16_t len);

void arp_packet_init(void)
{
	ethhdr->ether_type = htons(ETHERTYPE_ARP);

	arphdr->ea_hdr.ar_hrd = htons(0x0001); /* ethernet */
	arphdr->ea_hdr.ar_pro = htons(0x0800); /* IPv4 */
	arphdr->ea_hdr.ar_hln = ETH_ALEN;
	arphdr->ea_hdr.ar_pln = 4; /* IPv4 addr len */
}

int arp_packet_send(void)
{
	return socket_write(packet_buff, ARP_LEN);
}

static void tftp_packet_init(unsigned short src_port, unsigned short dst_port)
{
	ethhdr->ether_type = htons(ETH_P_IP);
	iphdr->version = 4;
	iphdr->ihl = 5;
	iphdr->tos = 0;
	iphdr->id = 0;
	iphdr->frag_off = 0;
	iphdr->ttl = 50;
	iphdr->protocol = IPPROTO_UDP;
	iphdr->saddr = local_ip;
	iphdr->daddr = remote_ip;
	udphdr->source = src_port;
	udphdr->dest = dst_port;
}

static int tftp_packet_send(int tftp_data_len)
{
	unsigned short sum;

	udphdr->len = htons(8 + tftp_data_len);

	/* UDP checksum */
	udphdr->check = 0;
	sum = ntohs(udphdr->len) + iphdr->protocol;
	sum = chksum(sum, (void *)&iphdr->saddr, 2 * sizeof(iphdr->saddr));
	sum = chksum(sum, (void *)udphdr, ntohs(udphdr->len));
	udphdr->check = ~(htons(sum));

	iphdr->tot_len = htons(20 + 8 + tftp_data_len);
	iphdr->check = 0;
	iphdr->check = ~(htons(chksum(0, (void *)iphdr, sizeof(struct iphdr))));

#if defined(PACKET_DEBUG)
	int i;

	for(i = 0; i < TFTP_BASE_LEN + tftp_data_len; i++)
		fprintf(stderr, "%02x%s", packet_buff[i], 15 == i % 16 ? "\n" : " ");

	if ((i % 16) != 0)
		fprintf(stderr, "\n");
#endif

	return socket_write(packet_buff, TFTP_BASE_LEN + tftp_data_len);
}

static int tftp_write_req(void)
{
	int tftp_data_len;

	tftp_packet_init(htons(TFTP_SRC_PORT), htons(IPPORT_TFTP));

	/* TFTP write request */
	*((unsigned short *)tftp_data) = htons(2);
	tftp_data_len = 2;
	tftp_data_len += sprintf((char *)(tftp_data + tftp_data_len), "\"%s\"", "flash_update");
	tftp_data_len += sprintf((char *)(tftp_data + tftp_data_len + 1), "%s", "octet");
	tftp_data_len += 2; /* sprintf does not count \0 */

	return tftp_packet_send(tftp_data_len);
}

static int read_from_file(void *target_buff, void *data, int len, int seek_pos)
{
	struct flash_from_file *fff = (struct flash_from_file *)data;
	int read_len = len;

	if (fff->file_size < seek_pos)
		read_len = 0;
	else if (fff->file_size < seek_pos + len)
		read_len = fff->file_size - seek_pos;

	if (read_len > 0) {
		if (read_len != read(fff->fd, target_buff, read_len)) {
			perror(fff->fname);
			return 1;
		}
	}

	if (read_len != len)
		memset(target_buff + read_len, 0, len - read_len);

	if (seek_pos == 0)
		memcpy(fff->buff, target_buff, 2);

	return 0;
}

static int tftp_transfer(const unsigned char *packet_buff, unsigned int packet_len)
{
	struct udphdr *rcv_udphdr = (struct udphdr *)packet_buff;
	unsigned short opcode, block;
	char *file_name;
	int tftp_data_len, ret;

	if ((flash_mode == MODE_REDBOOT) && (rcv_udphdr->dest != htons(IPPORT_TFTP)))
		return 1;

	if ((flash_mode == MODE_TFTP_CLIENT) && (rcv_udphdr->source != htons(IPPORT_TFTP)))
		return 1;

	opcode = ntohs(*(unsigned short *)(((char *)rcv_udphdr) + sizeof(struct udphdr)));
	block = ntohs(*(unsigned short *)(((char *)rcv_udphdr) + sizeof(struct udphdr) + 2));
	/* fprintf(stderr, "tftp opcode=%d, block=%d, len=%i\n", opcode,
		block, htons(rcv_udphdr->len) - sizeof(struct udphdr)); */

	switch (opcode) {
	/* TFTP read request */
	case 1:
		file_name = ((char *)rcv_udphdr) + sizeof(struct udphdr) + 2;
		if (strcmp(file_name, "kernel") == 0) {
			tftp_xfer_buff = (flash_from_file ? (unsigned char *)&fff_data[FFF_KERNEL] : kernel_buf);
			tftp_xfer_size = (flash_from_file ? fff_data[FFF_KERNEL].flash_size : kernel_size);
			printf("Sending kernel, %ld blocks...\n",
			       ((tftp_xfer_size + 511) / 512));
		} else if (strcmp(file_name, "rootfs") == 0) {
			tftp_xfer_buff = (flash_from_file ? (unsigned char *)&fff_data[FFF_ROOTFS] : rootfs_buf);
			tftp_xfer_size = (flash_from_file ? fff_data[FFF_ROOTFS].flash_size : rootfs_size);
			printf("Sending rootfs, %ld blocks...\n",
			       ((tftp_xfer_size + 511) / 512));
		} else {
			fprintf(stderr, "Unknown file name: %s\n", file_name);
			return -1;
		}

		block = 0;
		tftp_bytes_sent = 0;
		/* fall through - start sending data */
	/* TFTP ack */
	case 4:
		if (block == 0) {
			if ((xfer_in_progress == 0) &&
			    (flash_mode == MODE_TFTP_CLIENT))
				printf("Connection to TFTP server established - uploading %lu bytes of data ...\n", tftp_xfer_size);

			xfer_in_progress = 1;
			tftp_ack_block = 0;
			tftp_sent_block = 0;
		} else if (block != tftp_sent_block) {
			if (block < tftp_sent_block)
				fprintf(stderr, "tftp repeat block %d %d\n", block + 1, tftp_ack_block);
			else
				fprintf(stderr, "tftp acks unsent block %d (last sent block: %d)\n",
					block, tftp_sent_block);

			block = tftp_ack_block;
		} else {
			if (block * 512 > tftp_xfer_size) {
				if (flash_mode == MODE_TFTP_CLIENT) {
					printf("Image successfully transmitted.\n");
					printf("Please give the device a couple of minutes to install the new image into the flash.\n");
					return 0;
				}
				return 1;
			}

			tftp_ack_block = block;
		}

		block++;
		tftp_packet_init(rcv_udphdr->dest, rcv_udphdr->source);
		/* TFTP DATA packet */
		*((unsigned short *)tftp_data) = htons(3);
		*((unsigned short *)(tftp_data + 2)) = htons(block);

		tftp_data_len = tftp_xfer_size - tftp_bytes_sent > 512 ? 512 : tftp_xfer_size - tftp_bytes_sent;

		if (flash_from_file) {
			ret = read_from_file(tftp_data + 4, (void *)tftp_xfer_buff, tftp_data_len, tftp_bytes_sent);
			if (ret != 0)
				return -1;
		} else {
			memcpy(tftp_data + 4, (void *)(tftp_xfer_buff + tftp_bytes_sent), tftp_data_len);
		}

		tftp_bytes_sent += tftp_data_len;
		tftp_data_len += 4; /* opcode size */

		ret = tftp_packet_send(tftp_data_len);
		if (ret != 0)
			return -1;

		tftp_sent_block = block;
		/* printf("tftp data out: tftp_sent=%lu, remaining_size=%lu, data_len=%i, block=%d\n",
			tftp_sent, tftp_xfer_size - tftp_sent, tftp_data_len - 4, block); */
		break;
	/* TFTP error */
	case 5:
		if ((block == 2) && (htons(rcv_udphdr->len) - sizeof(struct udphdr) > 4))
			fprintf(stderr, "Received TFTP error: %s\n",
				((char *)rcv_udphdr) + sizeof(struct udphdr) + 4);
		else
			fprintf(stderr, "Received TFTP error code: %d\n", block);

		return -1;
		break;
	default:
		fprintf(stderr, "Unexpected TFTP opcode: %d\n", opcode);
		return -1;
		break;
	}

	return 1;
}

int fw_upload(void)
{
	const unsigned char *packet;
	struct ether_arp *rcv_arphdr;
	struct iphdr *rcv_iphdr;
	int len, ret;

	if (flash_mode == MODE_TFTP_CLIENT) {
		printf("Trying to connect to TFTP server on the device ..\n");
		ret = tftp_write_req();
		if (ret != 0)
			return ret;
	}

	while (1) {
		packet = socket_read(&len);

		if ((flash_mode == MODE_REDBOOT) && (tcp_status != TCP_CONTINUE)) {
			switch (tcp_status) {
			case TCP_SUCCESS:
				return 0;
			case TCP_ERROR:
				return 1;
			default:
				tcp_status = TCP_CONTINUE;
			}
		}

		if (!packet) {
			if (flash_mode == MODE_REDBOOT)
				handle_uip_conns();

			if (xfer_in_progress)
				continue;

#if defined(DEBUG)
			fprintf(stderr, "fw upload: waiting for transfer to begin ..\n");
#endif

			if (flash_mode == MODE_TFTP_CLIENT) {
				usleep(250000);

				if (write_req_timeout) {
					write_req_timeout--;
					continue;
				}

				fprintf(stderr, "TFTP connection timeout .. \n");
				tftp_write_req();
				if (ret != 0)
					return ret;

				write_req_timeout = 2;
			}

			usleep(250000);
			continue;
		}

		switch (ntohs(((struct ether_header *)packet)->ether_type)) {
		case ETHERTYPE_ARP:
			if (len < 60) {
				/* fprintf(stderr, "Expected arp with minimum length %i, received %d\n", 60, len); */
				continue;
			}

			rcv_arphdr = (struct ether_arp *)(packet + ETH_HLEN);

			switch (ntohs(rcv_arphdr->ea_hdr.ar_op)) {
			case ARPOP_REQUEST:
				if (*((unsigned int *)(rcv_arphdr->arp_tpa)) != local_ip)
					continue;

				/* fprintf(stderr, "Replying ARP request, opcode=%d\n",
					ntohs(rcv_arphdr->ea_hdr.ar_op)); */

				arp_packet_init();
				arphdr->ea_hdr.ar_op = htons(ARPOP_REPLY);
				memcpy(arphdr->arp_sha, ethhdr->ether_shost, ETH_ALEN);
				memcpy(arphdr->arp_tha, ethhdr->ether_dhost, ETH_ALEN);
				*((unsigned int *)arphdr->arp_spa) = local_ip;
				*((unsigned int *)arphdr->arp_tpa) = remote_ip;

				ret = arp_packet_send();
				if (ret != 0)
					return ret;
#if defined(DEBUG)
			fprintf(stderr, "fw upload: replied to ARP request ..\n");
#endif
				break;
			case ARPOP_REPLY:
				break;
			default:
				fprintf(stderr, "fw upload: unexpected arp packet, opcode=%d, tpa=%u\n",
					ntohs(rcv_arphdr->ea_hdr.ar_op),
					(unsigned int)ntohl(*((unsigned int *)(rcv_arphdr->arp_tpa))));
				continue;
			}

			/* we just replied to an ARP request - the TFTP server might try to find us */
			if (flash_mode == MODE_TFTP_CLIENT)
				write_req_timeout = 4;
			break;
		case ETH_P_IP:
			if (len < 20) {
				fprintf(stderr, "fw upload: expected IP with minimum length %i, received %d\n", 20, len);
				continue;
			}

			rcv_iphdr = (struct iphdr *)(packet + ETH_HLEN);

			if ((rcv_iphdr->saddr != remote_ip) ||
				(rcv_iphdr->daddr != local_ip))
				continue;

			if ((rcv_iphdr->protocol == IPPROTO_ICMP) && (!xfer_in_progress)
				&& (packet[ETH_HLEN + (rcv_iphdr->ihl * 4)] == ICMP_DEST_UNREACH)) {
				fprintf(stderr, "TFTP server not responding .. \n");
				continue;
			}

			switch (rcv_iphdr->protocol) {
			case IPPROTO_UDP:
				ret = tftp_transfer(packet + ETH_HLEN + (rcv_iphdr->ihl * 4),
						    len - ETH_HLEN - (rcv_iphdr->ihl * 4));

				if (ret < 0)
					return 1;  /* error */
				else if (ret == 0)
					return 0;  /* flash successful */
				break;
			case IPPROTO_TCP:
				handle_uip_tcp(packet, len);
				break;
			default:
				fprintf(stderr, "fw upload: unexpected IP packet: protocol=%d\n",
					rcv_iphdr->protocol);
				continue;
			}
			break;
		}
	}

	return 0;
}
