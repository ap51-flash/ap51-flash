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

#include <string.h>
#include <stdlib.h>

#include "socket.h"
#include "ap51-flash.h"

#if defined(NO_LIBPCAP)
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>

int raw_sock = -1;
unsigned char recv_packet_buff[2000];
#else
pcap_t *pcap_fp = NULL;
#endif

char *socket_find_dev_by_index(char *number)
{
#if defined(NO_LIBPCAP)
	return NULL;
#else
	pcap_if_t *alldevs = NULL, *d;
	char errbuf[PCAP_ERRBUF_SIZE], *pcap_dev = NULL;
	int i = 0, if_num = 0;

	if_num = strtol(number, NULL, 10);

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
		alldevs = NULL;

	/* Print the list */
	for (d = alldevs; d != NULL; d = d->next) {
		i++;

		if (if_num == i) {
			pcap_dev = strdup(d->name);
			break;
		}
	}

	if (alldevs)
		pcap_freealldevs(alldevs);

	return pcap_dev;
#endif
}

void socket_print_all_devices(void)
{
#if defined(NO_LIBPCAP)
	return;
#else
	pcap_if_t *alldevs = NULL, *d;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i = 0;

	/* Retrieve the device list from the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return;
	}

	/* Print the list */
	for(d = alldevs; d != NULL; d = d->next) {
		i++;
		fprintf(stderr, "\n%i: %s\n", i, d->name);

		if (!d->description) {
			fprintf(stderr, "\t(No description available)\n");
			continue;
		}

		unsigned char* p = (unsigned char*)d->description;
		unsigned char c = 0;
		fprintf(stderr, "\t(Description: ");
		while (' ' <= *p) {
			if (c != ' ' || c != *p)
				fprintf(stderr, "%c", *p);
			c = *p++;
		}

		fprintf(stderr, ")\n");
	}
#endif
}

int socket_open(char *dev)
{
#if defined(NO_LIBPCAP)
	struct sockaddr_ll addr;
	struct ifreq req;
	int ret;

	if (strlen(dev) > IFNAMSIZ - 1) {
		fprintf(stderr, "Error - interface name too long: %s\n", dev);
		goto out;
	}

	raw_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (raw_sock < 0) {
		fprintf(stderr, "Error - can't create raw socket: %s\n",
			strerror(errno));
		goto out;
	}

	memset(&req, 0, sizeof (struct ifreq));
	strncpy(req.ifr_name, dev, IFNAMSIZ);

	ret = ioctl(raw_sock, SIOCGIFFLAGS, &req);

	if (ret < 0) {
		fprintf(stderr, "Error - can't get interface flags (SIOCGIFFLAGS): %s\n",
			strerror(errno));
		goto close_sock;
	}

	req.ifr_flags |= IFF_PROMISC;
	ret = ioctl(raw_sock, SIOCSIFFLAGS, &req);

	if (ret < 0) {
		fprintf(stderr, "Error - can't set interface flags (SIOCSIFFLAGS): %s\n",
			strerror(errno));
		goto close_sock;
	}

	ret = ioctl(raw_sock, SIOCGIFINDEX, &req);

	if (ret < 0) {
		fprintf(stderr, "Error - can't get interface index (SIOCGIFINDEX): %s\n",
			strerror(errno));
		goto close_sock;
	}

	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = req.ifr_ifindex;

	ret = bind(raw_sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_ll));
	if (ret < 0) {
		fprintf(stderr, "Error - can't bind raw socket: %s\n", strerror(errno));
		goto close_sock;
	}

	return 0;

close_sock:
	close(raw_sock);
out:
	return 1;
#else
	char error[PCAP_ERRBUF_SIZE];

	/* Open the output adapter */
	pcap_fp = pcap_open_live(dev, 1500, 1, PCAP_TIMEOUT_MS, error);
	if (!pcap_fp) {
		fprintf(stderr, "Error opening adapter: %s\n", error);
		return 1;
	}

	return 0;
#endif
}

int socket_setnonblock(void)
{
#if defined(NO_LIBPCAP)
	int sock_opts;

	if (raw_sock < 0) {
		fprintf(stderr,"Error setting non-blocking mode: raw socket socket not initialized yet\n");
		return 1;
	}

	sock_opts = fcntl(raw_sock, F_GETFL, 0);
        fcntl(raw_sock, F_SETFL, sock_opts | O_NONBLOCK);

	return 0;
#else
	char error[PCAP_ERRBUF_SIZE];

	if (!pcap_fp) {
		fprintf(stderr,"Error setting non-blocking mode: pcap socket not initialized yet\n");
		return 1;
	}

	if (pcap_setnonblock(pcap_fp, 1, error) < 0) {
		fprintf(stderr,"Error setting non-blocking mode: %s\n", error);
		return 1;
	}

	return 0;
#endif
}

unsigned char *socket_read(int *len)
{
#if defined(NO_LIBPCAP)
	ssize_t read_len;

	if (raw_sock < 0) {
		fprintf(stderr,"Error reading from network: raw socket not initialized yet\n");
		return NULL;
	}

	read_len = read(raw_sock, recv_packet_buff, sizeof(recv_packet_buff));

	if (read_len > 0) {
		*len = (int)read_len;
		return recv_packet_buff;
	} else {
		*len = 0;
		return NULL;
	}

#else
	struct pcap_pkthdr hdr;
	const unsigned char *packet;

	if (!pcap_fp) {
		fprintf(stderr,"Error reading from network: pcap socket not initialized yet\n");
		return NULL;
	}

	packet = pcap_next(pcap_fp, &hdr);

	if (packet)
		*len = hdr.len;
	else
		*len = 0;

	return (unsigned char *)packet;
#endif
}

int socket_write(unsigned char *buff, int len)
{
#if defined(NO_LIBPCAP)
	if (raw_sock < 0) {
		fprintf(stderr,"Error writing to network: raw socket not initialized yet\n");
		return 1;
	}

	if (write(raw_sock, buff, len) < 0) {
		fprintf(stderr, "Error - can't write to raw socket: %s\n", strerror(errno));
		return 1;
	}

	return 0;
#else
	if (!pcap_fp) {
		fprintf(stderr,"Error writing to network: pcap socket not initialized yet\n");
		return 1;
	}

	if (pcap_sendpacket(pcap_fp, buff, len) < 0) {
		perror("pcap_sendpacket");
		return 1;
	}

	return 0;
#endif
}

void socket_close(char *dev)
{
#if defined(NO_LIBPCAP)
	struct ifreq req;
	int ret;

	memset(&req, 0, sizeof (struct ifreq));
	strncpy(req.ifr_name, dev, IFNAMSIZ);

	ret = ioctl(raw_sock, SIOCGIFFLAGS, &req);

	if (ret < 0) {
		fprintf(stderr, "Error - can't get interface flags (SIOCGIFFLAGS): %s\n",
			strerror(errno));
		goto close_sock;
	}

	req.ifr_flags &= ~IFF_PROMISC;
	ret = ioctl(raw_sock, SIOCSIFFLAGS, &req);

	if (ret < 0) {
		fprintf(stderr, "Error - can't set interface flags (SIOCSIFFLAGS): %s\n",
			strerror(errno));
		goto close_sock;
	}

close_sock:
	close(raw_sock);
#endif
}
