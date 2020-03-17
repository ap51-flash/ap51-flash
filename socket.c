// SPDX-License-Identifier: GPL-3.0-or-later
/* SPDX-FileCopyrightText: 2009-2019, Marek Lindner <mareklindner@neomailbox.ch>
 */

#include "socket.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "compat.h"

#ifdef USE_PCAP
#include "list.h"
#endif

enum listdump_action {
	/** @LISTDUMP_OK: continue processing */
	LISTDUMP_OK,

	/** @LISTDUMP_STOP: stop processing */
	LISTDUMP_STOP,
};

#if defined(LINUX)

static int raw_sock = -1;

static int socket_rtnl_recvmsg(int sock, struct nlmsghdr **nh,
			       unsigned int *len)
{
	ssize_t rlen;
	ssize_t ret;

peek_retry:
	rlen = recv(sock, NULL, 0, MSG_PEEK | MSG_TRUNC);
	if (rlen < 0) {
		if (errno == EINTR)
			goto peek_retry;

		fprintf(stderr,
			"Error - unable to retrieve netlink response: %s\n",
			strerror(errno));
		return rlen;
	}

	*nh = malloc(rlen);
	if (!*nh)
		return -ENOMEM;

recv_retry:
	ret = recv(sock, *nh, rlen, 0);
	if (ret < 0) {
		if (errno == EINTR)
			goto recv_retry;

		fprintf(stderr,
			"Error - unable to receive netlink request: %s\n",
			strerror(errno));
		goto free_resp;
	}

	*len = ret;

	return 0;

free_resp:
	free(*nh);
	*nh = NULL;

	return -1;
}

static char *sock_rta_find_name(struct ifinfomsg *ifinfomsg, size_t attr_len)
{
	struct rtattr *rta = IFLA_RTA(ifinfomsg);

	/* search the name */
	for (; RTA_OK(rta, attr_len); rta = RTA_NEXT(rta, attr_len)) {
		char *rta_data = RTA_DATA(rta);
		size_t rta_payload = RTA_PAYLOAD(rta);

		if (rta_payload <= 0)
			continue;

		if (rta->rta_type != IFLA_IFNAME)
			continue;

		rta_data[rta_payload - 1] = '\0';
		return rta_data;
	}

	return NULL;
}

static enum listdump_action socket_rtnl_parse(struct nlmsghdr *resp,
					      unsigned int len,
					      enum listdump_action (*dump)(const char *name,
									   unsigned int index,
									   const char *description,
									   void *arg),
					      void *arg)
{
	struct ifinfomsg *ifinfomsg;
	enum listdump_action action;
	struct nlmsgerr *nlme;
	struct nlmsghdr *nh;
	size_t attr_len;
	char *name;

	if (resp->nlmsg_type == NLMSG_ERROR) {
		nlme = NLMSG_DATA(resp);
		fprintf(stderr, "Error - netlink complained: %i\n",
			nlme->error);
		return LISTDUMP_STOP;
	}

	for (nh = resp; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
		if (nh->nlmsg_type == NLMSG_DONE)
			return LISTDUMP_STOP;

		if (nh->nlmsg_type != RTM_NEWLINK)
			continue;

		ifinfomsg = NLMSG_DATA(nh);
		attr_len = IFLA_PAYLOAD(nh);

		if (ifinfomsg->ifi_type != ARPHRD_ETHER)
			continue;

		name = sock_rta_find_name(ifinfomsg, attr_len);
		if (!name)
			continue;

		action = dump(name, ifinfomsg->ifi_index, NULL, arg);
		if (action == LISTDUMP_STOP)
			return action;
	}

	return LISTDUMP_OK;
}

static int socket_dump_ifaces(enum listdump_action (*dump)(const char *name,
							   unsigned int index,
							   const char *description,
							   void *arg),
			      void *arg)
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifinfomsg;
	} req;
	enum listdump_action action;
	struct sockaddr_nl nl;
	struct nlmsghdr *resp;
	int ret = -1, sock;
	unsigned int len;

	sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (sock < 0) {
		fprintf(stderr, "Error - can't create netlink socket: %s\n",
			strerror(errno));
		return sock;
	}

	memset(&nl, 0, sizeof(nl));
        nl.nl_family = AF_NETLINK;

        ret = bind(sock, (struct sockaddr *)&nl, sizeof(nl));
	if (ret < 0) {
		fprintf(stderr, "Error - can't bind netlink socket: %s\n",
			strerror(errno));
		goto close_sock;
	}

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifinfomsg));
	req.nh.nlmsg_type = RTM_GETLINK;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
	req.ifinfomsg.ifi_family = AF_UNSPEC;

	ret = send(sock, &req, sizeof(req), 0);
	if (ret < 0) {
		fprintf(stderr, "Error - unable to send netlink request: %s\n",
			strerror(errno));
		goto close_sock;
	}

	while (1) {
		resp = NULL;
		ret = socket_rtnl_recvmsg(sock, &resp, &len);
		if (ret < 0)
			goto close_sock;

		action = socket_rtnl_parse(resp, len, dump, arg);
		free(resp);

		if (action == LISTDUMP_STOP)
			break;
	}

	close(sock);
	return 0;

close_sock:
	close(sock);

	return ret;
}

#elif USE_PCAP

pcap_t *pcap_fp = NULL;

static int socket_dump_ifaces(enum listdump_action (*dump)(const char *name,
							   unsigned int index,
							   const char *description,
							   void *arg),
			      void *arg)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	enum listdump_action action;
	unsigned int if_count = 0;
	pcap_if_t *alldevs = NULL;
	pcap_if_t *dev;
	int ret;

	ret = pcap_findalldevs(&alldevs, errbuf);
	if (ret < 0) {
		fprintf(stderr,
			"Error - unable to retrieve interface list: %s\n",
			errbuf);
		return ret;
	}

	slist_for_each (dev, alldevs) {
		if (dev->flags & PCAP_IF_LOOPBACK)
			continue;

		if_count++;

		action = dump(dev->name, if_count, dev->description, arg);
		if (action == LISTDUMP_STOP)
			break;
	}

	if (alldevs)
		pcap_freealldevs(alldevs);

	return 0;
}

#else
#error socket_dump_ifaces() is not supported on your OS
#endif

struct socket_find_iface_by_index_arg {
	unsigned int index;
	char *name;
};

static enum listdump_action compare_interface(const char *name,
					      unsigned int index,
					      const char *description __attribute__((unused)),
					      void *arg)
{
	struct socket_find_iface_by_index_arg *find_arg = arg;

	if (index != find_arg->index)
		return LISTDUMP_OK;

	find_arg->name = strdup(name);

	return LISTDUMP_STOP;
}

char *socket_find_iface_by_index(const char *iface_number)
{
	struct socket_find_iface_by_index_arg find_arg = {
		.name = NULL,
	};
	char *endptr;
	long if_num;

	if_num = strtol(iface_number, &endptr, 10);
	if (!endptr || iface_number == endptr || *endptr != '\0')
		return NULL;

	if (if_num < 1)
		return NULL;

	find_arg.index = if_num;
	socket_dump_ifaces(compare_interface, &find_arg);

	return find_arg.name;
}

static void print_description_sanitized(const char *description)
{
	unsigned char last_char;
	unsigned char *ptr;
	unsigned char c;

	if (!description || strlen(description) == 0) {
		fprintf(stderr, "\t(No description available)\n");
		return;
	}

	fprintf(stderr, "\t(Description: ");

	ptr = (unsigned char *)description;
	last_char = 0;

	while (' ' <= *ptr) {
		c = *ptr;
		ptr++;

		/* skip multiple spaces */
		if (last_char == ' ' && last_char == c)
			continue;

		fprintf(stderr, "%c", c);
		last_char = c;
	}

	fprintf(stderr, ")\n");
}

static enum listdump_action print_interface(const char *name,
					    unsigned int index,
					    const char *description,
					    void *arg __attribute__((unused)))
{
	fprintf(stderr, "\n%i: %s\n", index, name);
	print_description_sanitized(description);

	return LISTDUMP_OK;
}

void socket_print_all_ifaces(void)
{
	socket_dump_ifaces(print_interface, NULL);
}

int socket_open(const char *iface)
{
#if defined(LINUX)
	struct sockaddr_ll addr;
	struct ifreq req;
	int ret, sock_opts;

	if (strlen(iface) > IFNAMSIZ - 1) {
		fprintf(stderr, "Error - interface name too long: %s\n",
			iface);
		goto out;
	}

	raw_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (raw_sock < 0) {
		fprintf(stderr, "Error - can't create raw socket: %s\n",
			strerror(errno));
		goto out;
	}

	memset(&req, 0, sizeof (struct ifreq));
	strncpy(req.ifr_name, iface, IFNAMSIZ);
	req.ifr_name[sizeof(req.ifr_name) - 1] = '\0';

	ret = ioctl(raw_sock, SIOCGIFFLAGS, &req);

	if (ret < 0) {
		if (errno == ENODEV)
			fprintf(stderr,
				"Error - interface does not exist: %s\n",
				iface);
		else
			fprintf(stderr,
				"Error - can't get interface flags (SIOCGIFFLAGS): %s\n",
				strerror(errno));
		goto close_sock;
	}

	if (!(req.ifr_flags & (IFF_UP | IFF_RUNNING))) {
		fprintf(stderr, "Error - interface is not up & running: %s\n",
			iface);
		goto close_sock;
	}

	req.ifr_flags |= IFF_PROMISC;
	ret = ioctl(raw_sock, SIOCSIFFLAGS, &req);

	if (ret < 0) {
		fprintf(stderr,
			"Error - can't set interface flags (SIOCSIFFLAGS): %s\n",
			strerror(errno));
		goto close_sock;
	}

	ret = ioctl(raw_sock, SIOCGIFINDEX, &req);

	if (ret < 0) {
		fprintf(stderr,
			"Error - can't get interface index (SIOCGIFINDEX): %s\n",
			strerror(errno));
		goto close_sock;
	}

	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = req.ifr_ifindex;

	ret = bind(raw_sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_ll));
	if (ret < 0) {
		fprintf(stderr, "Error - can't bind raw socket: %s\n",
			strerror(errno));
		goto close_sock;
	}

	sock_opts = fcntl(raw_sock, F_GETFL, 0);
	if (sock_opts == -1) {
		fprintf(stderr, "Error - can't read socket flags: %s\n",
			strerror(errno));
		goto close_sock;
	}

	ret = fcntl(raw_sock, F_SETFL, sock_opts | O_NONBLOCK);
	if (ret < 0) {
		fprintf(stderr, "Error - can't set socket flags: %s\n",
			strerror(errno));
		goto close_sock;
	}

	return 0;

close_sock:
	close(raw_sock);
	raw_sock = -1;
out:
	return -1;
#elif USE_PCAP

	char error[PCAP_ERRBUF_SIZE];

#if WIN32
	pcap_fp = pcap_open_live(iface, 1500, 1, 250, error);
	if (!pcap_fp) {
		fprintf(stderr, "Error opening adapter: %s\n", error);
		return -1;
	}
	if (pcap_setmintocopy(pcap_fp, 1) < 0) {
		fprintf(stderr, "Error setting mintocopy: %s\n", error);
		return 1;
	}
#else
	// For Mac OS X, and maybe others in the future,
	// we take the long way around and set individual options on pcap
	// in order to be able to set immediate mode before activating the pcap
	// handle.

	int ret;

	pcap_fp = pcap_create(iface, error);
	if (!pcap_fp) {
		fprintf(stderr, "Error opening adapter: %s\n", error);
		return -1;
	}

	ret = pcap_set_snaplen(pcap_fp, 1500);
	if (ret != 0) {
		fprintf(stderr, "Error setting pcap snaplen: %s\n", error);
		return -1;
	}

	ret = pcap_set_promisc(pcap_fp, 1);
	if (ret != 0) {
		fprintf(stderr, "Error setting pcap promiscuous mode: %s\n",
			error);
		return -1;
	}

	ret = pcap_set_timeout(pcap_fp, 250);
	if (ret != 0) {
		fprintf(stderr, "Error setting pcap timeout: %s\n", error);
		return -1;
	}

	ret = pcap_set_immediate_mode(pcap_fp, 1);
	if (ret != 0) {
		fprintf(stderr, "Error setting pcap immediate mode: %s\n",
			error);
		return -1;
	}

	ret = pcap_activate(pcap_fp);
	if (ret != 0) {
		fprintf(stderr, "Error activating pcap handle\n");
		return -1;
	}
#endif

	return 0;
#else
#error socket_open() is not supported on your OS
	return -1;
#endif
}

#if defined(USE_PCAP)
int socket_read(char *packet_buff, int packet_buff_len,
		int (*sleep_sec)__attribute__((unused)),
		int (*sleep_usec)__attribute__((unused)))
#else
int socket_read(char *packet_buff, int packet_buff_len, int *sleep_sec,
		int *sleep_usec)
#endif
{
#if defined(LINUX)
	struct timeval tv;
	fd_set watched_fds;
	ssize_t read_len;
	int ret = -1;

	if (raw_sock < 0) {
		fprintf(stderr,
			"Error reading from network: raw socket not initialized yet\n");
		goto out;
	}

	FD_ZERO(&watched_fds);
	FD_SET(raw_sock, &watched_fds);

	tv.tv_sec = *sleep_sec;
	tv.tv_usec = *sleep_usec;

	ret = select(raw_sock + 1, &watched_fds, NULL, NULL, &tv);

	*sleep_sec = tv.tv_sec;
	*sleep_usec = tv.tv_usec;

	if (ret < 0) {
		if (errno != EINTR)
			fprintf(stderr,
				"Error waiting for data from network: %s",
				strerror(errno));
	}

	if (ret <= 0)
		goto out;

	read_len = read(raw_sock, packet_buff, packet_buff_len - 1);

	if (read_len < 0) {
		if ((errno != EWOULDBLOCK) && (errno != EINTR))
			fprintf(stderr, "Error reading data from network: %s",
				strerror(errno));
	}

	ret = (int)read_len;
	packet_buff[read_len] = '\0';

out:
	return ret;
#elif USE_PCAP

	struct pcap_pkthdr hdr;
	const unsigned char *tmp_packet;
	int ret = -1;

	if (!pcap_fp) {
		fprintf(stderr,
			"Error reading from network: pcap socket not initialized yet\n");
		goto out;
	}

	ret = 0;
	tmp_packet = pcap_next(pcap_fp, &hdr);

	if ((tmp_packet) && (hdr.len > 0)) {
		ret = hdr.len;
		if (ret > packet_buff_len)
			ret = packet_buff_len;
		memcpy(packet_buff, tmp_packet, ret);
		packet_buff[ret] = '\0';
	}
out:
	return ret;
#else
#error socket_read() is not supported on your OS
	return 0;
#endif
}

int socket_write(const char *buff, int len)
{
#if defined(LINUX)
	int ret = -1;

	if (raw_sock < 0) {
		fprintf(stderr,
			"Error writing to network: raw socket not initialized yet\n");
		goto out;
	}

	ret = write(raw_sock, buff, len);

	if (ret < 0)
		fprintf(stderr,
			"Error - can't write to raw socket: %s\n",
			strerror(errno));

out:
	return ret;
#elif USE_PCAP
	int ret = -1;

	if (!pcap_fp) {
		fprintf(stderr,
			"Error writing to network: pcap socket not initialized yet\n");
		goto out;
	}

	ret = pcap_sendpacket(pcap_fp, (unsigned char *)buff, len);

	if (ret < 0)
		fprintf(stderr, "Error - can't write to pcap socket\n");

out:
	return ret;
#else
#error socket_write() is not supported on your OS
	return 0;
#endif
}

void socket_close(const char *iface)
{
#if defined(LINUX)
	struct ifreq req;
	int ret;

	if (raw_sock < 0)
		goto out;

	memset(&req, 0, sizeof (struct ifreq));
	strncpy(req.ifr_name, iface, IFNAMSIZ);
	req.ifr_name[sizeof(req.ifr_name) - 1] = '\0';

	ret = ioctl(raw_sock, SIOCGIFFLAGS, &req);

	if (ret < 0) {
		fprintf(stderr,
			"Error - can't get interface flags (SIOCGIFFLAGS): %s (%i)\n",
			strerror(errno), raw_sock);
		goto close_sock;
	}

	req.ifr_flags &= ~IFF_PROMISC;
	ret = ioctl(raw_sock, SIOCSIFFLAGS, &req);

	if (ret < 0) {
		fprintf(stderr,
			"Error - can't set interface flags (SIOCSIFFLAGS): %s\n",
			strerror(errno));
		goto close_sock;
	}

close_sock:
	close(raw_sock);
	raw_sock = -1;
out:
	return;
#elif USE_PCAP
	if (!pcap_fp) {
		fprintf(stderr,
			"Error closing adapter '%s': pcap socket not initialized yet\n",
			iface);
		goto out;
	}

	pcap_close(pcap_fp);

out:
	return;
#else
#error socket_close() is not supported on your OS
#endif
}
