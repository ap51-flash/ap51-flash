/*
 * Copyright (C) open-mesh inc
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
#include <string.h>

#include "packet.h"

#define PACKET_BUFF_LEN 1500

unsigned char packet_buff[PACKET_BUFF_LEN];
struct ether_header *ethhdr = (struct ether_header *)packet_buff;
struct ether_arp *arphdr = (struct ether_arp *)(packet_buff + sizeof(struct ether_header));
struct iphdr *iphdr = (struct iphdr *)(packet_buff + sizeof(struct ether_header));
struct udphdr *udphdr = (struct udphdr *)(packet_buff + sizeof(struct ether_header) + sizeof(struct iphdr));
struct tcphdr *tcphdr = (struct tcphdr *)(packet_buff + sizeof(struct ether_header) + sizeof(struct iphdr));
void *tftp_data = (void *)(packet_buff + TFTP_BASE_LEN);


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

void arp_packet_send(void)
{
	if (!pcap_sendpacket(pcap_fp, packet_buff, ARP_LEN))
		return;

	perror("pcap_sendpacket");
	exit(1);
}

static void tftp_packet_init(void)
{
	ethhdr->ether_type = htons(ETH_P_IP);
	iphdr->version = 4;
	iphdr->ihl = 5;
	iphdr->tos = 0;
	iphdr->id = 0;
	iphdr->frag_off = 0;
	iphdr->ttl = 50;
	iphdr->protocol = IPPROTO_UDP;
	iphdr->saddr = htonl(tftp_local_ip);
	iphdr->daddr = htonl(tftp_remote_ip);
	udphdr->source = htons(TFTP_SRC_PORT);
	udphdr->dest = htons(IPPORT_TFTP);
}

static void tftp_packet_send(int tftp_data_len)
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

#if defined(_DEBUG)
	int i;

	for(i = 0; i < TFTP_BASE_LEN + tftp_data_len; i++)
		fprintf(stderr, "%02x%s", packet_buff[i], 15 == i % 16 ? "\n" : " ");
	if (0 != i % 16) fprintf(stderr, "\n");
#endif

	if (!pcap_sendpacket(pcap_fp, packet_buff, TFTP_BASE_LEN + tftp_data_len))
		return;

	perror("pcap_sendpacket");
	exit(1);
}

static void tftp_write_req(void)
{
	int tftp_data_len;

	tftp_packet_init();

	/* tftp write request */
	*((unsigned short *)tftp_data) = htons(2);
	tftp_data_len = 2;
	tftp_data_len += sprintf((char *)(tftp_data + tftp_data_len), "\"%s\"", "flash_update");
	tftp_data_len += sprintf((char *)(tftp_data + tftp_data_len + 1), "%s", "octet");
	tftp_data_len += 2; /* sprintf does not count \0 */

	tftp_packet_send(tftp_data_len);
}

void tftp_transfer(void)
{
	const unsigned char* packet;
	struct pcap_pkthdr hdr;
	struct iphdr *rcv_iphdr;
	struct udphdr *rcv_udphdr;
	unsigned short opcode, block, ack_block = 0, sent_block = 0;
	unsigned long tftp_sent = 0;
	int xfer_status = 0, tftp_data_len = 0, write_req_timeout = 4;

	printf("Trying to connect to TFTP server on the device ..\n");
	tftp_write_req();

	while (1) {
		packet = pcap_next(pcap_fp, &hdr);

		if (!packet) {
			if (xfer_status)
				continue;

			usleep(500000);
			if (write_req_timeout) {
				write_req_timeout--;
				continue;
			}

			printf("TFTP connection timeout .. \n");
			tftp_write_req();
			write_req_timeout = 2;

			continue;
		}

		switch (ntohs(((struct ether_header *)packet)->ether_type)) {
		case ETHERTYPE_ARP:
			if (hdr.len != 60) {
#if defined(_DEBUG)
				fprintf(stderr, "Expected arp with length %i, received %d\n", 60, hdr.len);
#endif
				continue;
			}

			if ((ntohs(((struct arphdr *)(packet + ETH_HLEN))->ar_op) == ARPOP_REQUEST) &&
					(*((unsigned int *)(((struct ether_arp *)(packet + ETH_HLEN))->arp_tpa)) == htonl(tftp_local_ip))) {

				/* fprintf(stderr, "Replying ARP request, opcode=%d\n",
					ntohs(((struct arphdr*)(packet + ETH_HLEN))->ar_op)); */

				arp_packet_init();
				arphdr->ea_hdr.ar_op = htons(ARPOP_REPLY);
				memcpy(arphdr->arp_sha, ethhdr->ether_shost, ETH_ALEN);
				memcpy(arphdr->arp_tha, ethhdr->ether_dhost, ETH_ALEN);
				*((unsigned int *)arphdr->arp_spa) = htonl(tftp_local_ip);
				*((unsigned int *)arphdr->arp_tpa) = htonl(tftp_remote_ip);
				arp_packet_send();
				/* we just replied to an ARP request - the TFTP server might try to find us */
				write_req_timeout = 4;
			} else {
				fprintf(stderr, "Unexpected arp packet, opcode=%d, tpa=%u\n",
					ntohs(((struct arphdr *)(packet + ETH_HLEN))->ar_op),
					(unsigned int)ntohl(*((unsigned int *)(((struct ether_arp *)(packet + ETH_HLEN))->arp_tpa))));
			}

			break;

		case ETH_P_IP:
			rcv_iphdr = (struct iphdr *)(packet + ETH_HLEN);

			if ((rcv_iphdr->saddr != htonl(tftp_remote_ip)) ||
				(rcv_iphdr->daddr != htonl(tftp_local_ip)))
				break;

			if ((rcv_iphdr->protocol == IPPROTO_ICMP) && (!xfer_status)
				&& (packet[ETH_HLEN + (rcv_iphdr->ihl * 4)] == ICMP_DEST_UNREACH)) {
				printf("TFTP server not responding .. \n");
				break;
			}

			if (rcv_iphdr->protocol != IPPROTO_UDP)
				break;

			rcv_udphdr = (struct udphdr *)(packet + ETH_HLEN + (rcv_iphdr->ihl * 4));

			if (rcv_udphdr->dest != htons(TFTP_SRC_PORT))
				break;

			opcode = ntohs(*(unsigned short *)(((char *)rcv_udphdr) + sizeof(struct udphdr)));
			block = ntohs(*(unsigned short *)(((char *)rcv_udphdr) + sizeof(struct udphdr) + 2));
			/* fprintf(stderr, "tftp opcode=%d, block=%d, len=%i\n", opcode,
				block, htons(rcv_udphdr->len) - sizeof(struct udphdr)); */

			switch (opcode) {
			/* TFTP ack */
			case 4:
				if (block == 0) {
					if (xfer_status == 0)
						printf("Connection to TFTP server established - uploading %i bytes of data ...\n", rootfs_size);

					xfer_status = 1;
					ack_block = 0;
					tftp_sent = 0;
				} else if (block != sent_block) {
					if (block < sent_block)
						fprintf(stderr, "tftp repeat block %d %d\n", block + 1, ack_block);
					else
						fprintf(stderr, "tftp acks unsent block %d (last sent block: %d)\n",
							block, sent_block);

					block = ack_block;
				} else {
					if (block * 512 > rootfs_size) {
						printf("Image successfully transmitted.\n");
						printf("Please give the device a couple of minutes to install the new image into the flash.\n");
						return;
					}

					ack_block = block;
				}

				block++;
				tftp_packet_init();
				/* TFTP DATA packet */
				*((unsigned short *)tftp_data) = htons(3);
				*((unsigned short *)(tftp_data + 2)) = htons(block);

				if (rootfs_size - tftp_sent >= 512) {
					memcpy(tftp_data + 4, (void *)(rootfs_buf + tftp_sent), 512);
					tftp_data_len = 512;
				} else {
					memcpy(tftp_data + 4, (void *)(rootfs_buf + tftp_sent), rootfs_size - tftp_sent);
					tftp_data_len = rootfs_size - tftp_sent;
				}

				tftp_sent += tftp_data_len;
				tftp_data_len += 4; /* opcode size */
				tftp_packet_send(tftp_data_len);
				sent_block = block;
				/* printf("tftp data out: tftp_sent=%lu, remaining_size=%lu, data_len=%i, block=%d\n",
					tftp_sent, rootfs_size - tftp_sent, tftp_data_len - 4, block); */
				break;
			/* TFTP error */
			case 5:
				if ((block == 2) && (htons(rcv_udphdr->len) - sizeof(struct udphdr) > 4))
					fprintf(stderr, "Received TFTP error: %s\n",
						((char *)rcv_udphdr) + sizeof(struct udphdr) + 4);
				else
					fprintf(stderr, "Received TFTP error code: %d\n", block);
				exit(1);
				break;
			default:
				fprintf(stderr, "Unexpected TFTP opcode: %d\n", opcode);
				exit(1);
				break;
			}
		}
	}
}

static void tcp_packet_send(void)
{
	unsigned short sum;

	/* TCP checksum */
	tcphdr->check = 0;
	sum = sizeof(struct tcphdr) + iphdr->protocol;
	sum = chksum(sum, (void *)&iphdr->saddr, 2 * sizeof(iphdr->saddr));
	sum = chksum(sum, (void *)tcphdr, sizeof(struct tcphdr));
	tcphdr->check = ~(htons(sum));

	iphdr->tot_len = htons(20 + sizeof(struct tcphdr));
	iphdr->check = 0;
	iphdr->check = ~(htons(chksum(0, (void *)iphdr, sizeof(struct iphdr))));

#if defined(_DEBUG)
	int i;

	for(i = 0; i < TCP_BASE_LEN; i++)
		fprintf(stderr, "%02x%s", packet_buff[i], 15 == i % 16 ? "\n" : " ");
	if (0 != i % 16) fprintf(stderr, "\n");
#endif

	if (!pcap_sendpacket(pcap_fp, packet_buff, TCP_BASE_LEN))
		return;

	perror("pcap_sendpacket");
	exit(1);
}

static void tcp_send_packet(unsigned int src_addr, unsigned int dst_addr, unsigned short dst_port)
{
	ethhdr->ether_type = htons(ETH_P_IP);
	iphdr->version = 4;
	iphdr->ihl = 5;
	iphdr->tos = 0;
	iphdr->id = 0;
	iphdr->frag_off = 0;
	iphdr->ttl = 50;
	iphdr->protocol = IPPROTO_TCP;
	iphdr->saddr = src_addr;
	iphdr->daddr = dst_addr;
	tcphdr->source = htons(TFTP_SRC_PORT);
	tcphdr->dest = dst_port;
	tcphdr->doff = 5;
	tcphdr->window = htons(4146);

	tcp_packet_send();
}

static void tcp_send_syn_packet(unsigned int src_addr, unsigned int dst_addr, unsigned short dst_port)
{
	memset(tcphdr, 0, sizeof(struct tcphdr));
	tcphdr->syn = 1;
	tcp_send_packet(src_addr, dst_addr, dst_port);
}

int tcp_port_scan(unsigned int src_addr, unsigned int dst_addr, unsigned short dst_port)
{
	const unsigned char* packet;
	struct pcap_pkthdr hdr;
	struct iphdr *rcv_iphdr;
	struct tcphdr *rcv_tcphdr;
	int tcp_send_timeout = 50;

	tcp_send_syn_packet(src_addr, dst_addr, dst_port);

	while (1) {
		packet = pcap_next(pcap_fp, &hdr);

		if (!packet) {
			if (!tcp_send_timeout)
				goto err;

			usleep(125000);
			tcp_send_timeout--;

			tcp_send_syn_packet(src_addr, dst_addr, dst_port);
			continue;
		}

		switch (ntohs(((struct ether_header *)packet)->ether_type)) {
		case ETH_P_IP:
			rcv_iphdr = (struct iphdr *)(packet + ETH_HLEN);

			if ((rcv_iphdr->saddr != dst_addr) ||
				(rcv_iphdr->daddr != src_addr))
				break;

			if ((rcv_iphdr->protocol == IPPROTO_ICMP)
				&& (packet[ETH_HLEN + (rcv_iphdr->ihl * 4)] == ICMP_DEST_UNREACH)) {
				break;
			}

			if (rcv_iphdr->protocol != IPPROTO_TCP)
				break;

			rcv_tcphdr = (struct tcphdr *)(packet + ETH_HLEN + (rcv_iphdr->ihl * 4));

			if (rcv_tcphdr->dest != htons(TFTP_SRC_PORT))
				break;

			/* printf("tcp packet received, flags [%c%c%c%c%c%c]\n",
				(rcv_tcphdr->fin ? 'F' : '.'), (rcv_tcphdr->syn ? 'S' : '.'),
				(rcv_tcphdr->rst ? 'R' : '.'), (rcv_tcphdr->psh ? 'P' : '.'),
				(rcv_tcphdr->ack ? 'A' : '.'), (rcv_tcphdr->urg ? 'U' : '.')); */

			if (rcv_tcphdr->rst)
				break;

			if ((rcv_tcphdr->syn) && (rcv_tcphdr->ack))
				return 0;

			break;
		}
	}

err:
	return -1;
}
