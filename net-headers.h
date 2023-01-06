/*
 * This file is part of fraud-bridge.
 *
 * (C) 2013-2023 by Sebastian Krahmer
 *                  sebastian [dot] krahmer [at] gmail [dot] com
 *
 * fraud-bridge is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * fraud-bridge is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with fraud-bridge.  If not, see <http://www.gnu.org/licenses/>.
 */

/* some of the header definitions have been taken from various other
 * open-sourced include files
 */

#ifndef fraudbriedge_net_headers
#define fraudbriedge_net_headers

#include <sys/types.h>
#include <bits/endian.h>
#include <cstdint>
#include <netinet/in.h>


namespace fraudbridge {


namespace net_headers {


struct tap_header {
	uint16_t flags, proto;
} __attribute__((packed));


struct icmphdr {
   	uint8_t type;
        uint8_t code;
        uint16_t sum;

	union {
		struct {
                   	uint16_t id;
                        uint16_t sequence;
                } echo;
	        uint32_t gateway;
		struct {
                   	uint16_t unused;
                        uint16_t mtu;
                } frag;
        } un;
};


enum eth_types_t : uint16_t {
	ETH_P_IP	= 0x0800
};


enum icmp_type : uint8_t {
	ICMP_ECHO_REPLY		=	0,
	ICMP_ECHO_REQUEST	=	8,

	ICMP6_ECHO_REQUEST	= 128,
	ICMP6_ECHO_REPLY	= 129
};


class udphdr {
public:
   	uint16_t	source;
        uint16_t	dest;
        uint16_t	len;
        uint16_t	check;

	udphdr() : source(0), dest(0), len(0), check(0) { }
};


/*
 *  The pseudo-header is used to calculate checksums over UDP
 *  and TCP packets.
 */
struct pseudohdr {
   	uint32_t saddr;
        uint32_t daddr;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
};


struct pseudohdr6 {
	in6_addr saddr, daddr;
	uint32_t len;
	uint8_t zero[3];
	uint8_t proto;
};


enum tcp_flags_t : uint8_t {
	TH_FIN	=	0x01,
	TH_SYN	=	0x02,
	TH_RST	=	0x04,
	TH_PUSH	=	0x08,
	TH_ACK	=	0x10,
	TH_URG	=	0x20
};


class tcphdr
{
public:
    	uint16_t th_sport;
        uint16_t th_dport;
        uint32_t th_seq;
        uint32_t th_ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    	uint8_t th_x2:4;		// unused
        uint8_t th_off:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    	uint8_t th_off:4;
        uint8_t th_x2:4;
#endif
    	uint8_t th_flags;

    	uint16_t th_win;
        uint16_t th_sum;
        uint16_t th_urg;
};


enum tcp_opt_t : uint8_t {
	TCPOPT_EOL	=	0,
	TCPOPT_NOP	=	1,
	TCPOPT_MAXSEG	=	2,
	TCPOLEN_MAXSEG	=	4,
	TCPOPT_WINDOW	=	3,
	TCPOLEN_WINDOW	=	3,
	TCPOPT_SACK_PERMITTED =	4,			// Experimental
	TCPOLEN_SACK_PERMITTED=	2,
	TCPOPT_SACK	=	5,			// Experimental
	TCPOPT_TIMESTAMP   =	8,
	TCPOLEN_TIMESTAMP  =	10,
	TCPOLEN_TSTAMP_APPA  =	(TCPOLEN_TIMESTAMP+2),	// appendix A
	TCPOPT_QSR	=	27,
	TCPOLEN_QSR	=	8
};


class iphdr
{
public:
#if __BYTE_ORDER == __LITTLE_ENDIAN
    	uint32_t ihl:4;
        uint32_t version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    	uint32_t version:4;
        uint32_t ihl:4;
#else
# error	"Please fix <bits/endian.h>"
#endif
    	uint8_t tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t check;
        uint32_t saddr;
        uint32_t daddr;

	iphdr() : ihl(5), version(4), tos(0), tot_len(0), id(0), frag_off(0),
	          ttl(64), protocol(IPPROTO_IP), check(0), saddr(0), daddr(0) { }
};


enum ip_flags_t : uint16_t {
	IP_RF = 0x8000,
	IP_DF = 0x4000,
	IP_MF = 0x2000,
	IP_OFFMASK = 0x1fff
};


struct ip6_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t                priority:4,
                                version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t                version:4,
                	        priority:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	uint8_t                flow_lbl[3];

	uint16_t               payload_len;
	uint8_t                nexthdr;
	uint8_t                hop_limit;

        struct  in6_addr        saddr;
        struct  in6_addr        daddr;
};


struct ip6_opt {
	uint8_t  ip6o_type;
	uint8_t  ip6o_len;
};


struct icmp6_hdr {
	uint8_t icmp6_type;			// type field
	uint8_t icmp6_code;			// code field
	uint16_t icmp6_cksum;			// checksum field
	union {
		uint32_t icmp6_un_data32[1];	// type-specific field
		uint16_t icmp6_un_data16[2];	// type-specific field
		uint8_t icmp6_un_data8[4];	// type-specific field
	} icmp6_dataun;
};



class dnshdr {
public:
	uint16_t id;

#if __BYTE_ORDER == __BIG_ENDIAN
                        /* fields in third byte */
        uint16_t        qr: 1;          /* response flag */
        uint16_t        opcode: 4;      /* purpose of message */
        uint16_t        aa: 1;          /* authoritive answer */
        uint16_t        tc: 1;          /* truncated message */
        uint16_t        rd: 1;          /* recursion desired */
                        /* fields in fourth byte */
        uint16_t        ra: 1;          /* recursion available */
        uint16_t        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        uint16_t        ad: 1;          /* authentic data from named */
        uint16_t        cd: 1;          /* checking disabled by resolver */
        uint16_t        rcode :4;       /* response code */
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
                        /* fields in third byte */
        uint16_t        rd :1;          /* recursion desired */
        uint16_t        tc :1;          /* truncated message */
        uint16_t        aa :1;          /* authoritive answer */
        uint16_t        opcode :4;      /* purpose of message */
        uint16_t        qr :1;          /* response flag */
                        /* fields in fourth byte */
        uint16_t        rcode :4;       /* response code */
        uint16_t        cd: 1;          /* checking disabled by resolver */
        uint16_t        ad: 1;          /* authentic data from named */
        uint16_t        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        uint16_t        ra :1;          /* recursion available */
#endif
/*
        union {
		u_int16_t flags;

		u_int16_t QR:1;
		u_int16_t opcode:4;
		u_int16_t AA:1;
		u_int16_t TC:1;
		u_int16_t RD:1;
		u_int16_t RA:1;
		u_int16_t zero:3;
		u_int16_t rcode:4;
        } u;
*/
	uint16_t q_count;
	uint16_t a_count;
	uint16_t rra_count;
	uint16_t ad_count;

	dnshdr() : id (0),
	           q_count(0), a_count(0), rra_count(0), ad_count(0)
	{
		qr = 0; opcode = 0; aa = 0; tc = 0; rd = 0; ra = 0; ad = 0; cd = 0;
		rcode = 0; unused = 0;
	}

	private: dnshdr(const dnshdr &) {};
};


enum dns_type : uint16_t {
	A	=	1,
	NS	=	2,
	CNAME	=	5,
	HINFO	=	13,
	MX	=	15,
	TXT	=	16,
	OPT	=	41
};


// an IPv4 A RR
struct dns_rr {
	// name here
	uint16_t type, _class;
	uint32_t ttl;
	uint16_t len;
	char data[4];
} __attribute__((packed));


} // namespace

} // namespace

#endif

