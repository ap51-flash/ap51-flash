/* SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: Marek Lindner <marek.lindner@mailbox.org>
 */

#ifndef __AP51_FLASH_COMPAT_H__
#define __AP51_FLASH_COMPAT_H__

#if defined(LINUX)

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define O_BINARY 0
#define USE_PCAP 0


#elif defined(OSX)

#include <arpa/inet.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <pcap.h>

#define O_BINARY 0
#define USE_PCAP 1

#define ETH_ALEN        6
#define ETH_HLEN        14
#define ETH_DATA_LEN    1500

#elif defined(WIN32)

#define USE_PCAP 1

#include <pcap.h>

#define ntohs(x) __swab16(x)
#define htons(x) __swab16(x)
#define htonl(x) __swab32(x)
#define ntohl(x) __swab32(x)

#define ETH_ALEN        6
#define ETH_HLEN        14
#define ETH_DATA_LEN    1500

struct ether_header {
    uint8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
    uint8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
    uint16_t ether_type;		/* packet type ID field	*/
} __attribute__((packed));

struct arphdr {
    uint16_t ar_hrd;		/* format of hardware address	*/
    uint16_t ar_pro;		/* format of protocol address	*/
    uint8_t	ar_hln;		/* length of hardware address	*/
    uint8_t	ar_pln;		/* length of protocol address	*/
    uint16_t ar_op;		/* ARP opcode (command)		*/
} __attribute__((packed));

struct ether_arp {
    struct  arphdr ea_hdr;	/* fixed-size header */
    uint8_t arp_sha[ETH_ALEN];	/* sender hardware address */
    uint8_t arp_spa[4];		/* sender protocol address */
    uint8_t arp_tha[ETH_ALEN];	/* target hardware address */
    uint8_t arp_tpa[4];		/* target protocol address */
} __attribute__((packed));

#endif


#ifndef IPPORT_TFTP
#define IPPORT_TFTP	69
#endif

#ifndef IPPORT_ICMP
#define IPPORT_ICMP	1
#endif

#if USE_PCAP

#define ETH_P_IP	0x0800
#define ETH_P_ARP	0x0806

#define IPPROTO_TCP	6
#define IPPROTO_UDP	17

#define IPPORT_TFTP	69

#define ARPOP_REQUEST	1
#define ARPOP_REPLY	2

#define __swab16(x) ((uint16_t)(                     \
        (((uint16_t)(x) & (uint16_t)0x00ffU) << 8) | \
        (((uint16_t)(x) & (uint16_t)0xff00U) >> 8)))

#define __swab32(x) ((uint32_t)(                            \
        (((uint32_t)(x) & (uint32_t)0x000000ffUL) << 24) |  \
        (((uint32_t)(x) & (uint32_t)0x0000ff00UL) <<  8) |  \
        (((uint32_t)(x) & (uint32_t)0x00ff0000UL) >>  8) |  \
        (((uint32_t)(x) & (uint32_t)0xff000000UL) >> 24)))

#define iphdr iphdr_linux
#define udphdr udphdr_linux
#define tcphdr tcphdr_linux
#define icmphdr icmphdr_linux

struct iphdr_linux {
    uint8_t ihl:4;
    uint8_t version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct udphdr_linux {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

struct tcphdr_linux {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1:4,
             doff:4,
             fin:1,
             syn:1,
             rst:1,
             psh:1,
             ack:1,
             urg:1,
             ece:1,
             cwr:1;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct icmphdr_linux
{
	uint8_t type;		/* message type */
	uint8_t code;		/* type sub-code */
	uint16_t checksum;
	union {
		struct {
			uint16_t	id;
			uint16_t	sequence;
		} echo; /* echo datagram */
		uint32_t gateway; /* gateway address */
		struct {
			uint16_t __unused;
			uint16_t mtu;
		} frag; /* path mtu discovery */
	} un;
};

#endif

#endif /* __AP51_FLASH_COMPAT_H__ */
