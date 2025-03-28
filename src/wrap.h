/*
 * This file is part of fraud-bridge.
 *
 * (C) 2013-2023 by Sebastian Krahmer,
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

#ifndef fraudbridge_wrap_h
#define fraudbridge_wrap_h

#include <string.h>
#include <cstdint>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "net-headers.h"
#include "dns.h"

extern "C" {
#include <openssl/evp.h>
}


namespace fraudbridge {


enum wrap_t : unsigned int {
	WRAP_INVALID		= 0,

	WRAP_REQUEST		= 1,
	WRAP_REPLY		= 2,

	WRAP_ICMP		= 0x1000,
	WRAP_ICMP_REQUEST	= WRAP_ICMP|WRAP_REQUEST,
	WRAP_ICMP_REPLY		= WRAP_ICMP|WRAP_REPLY,

	WRAP_ICMP6		= 0x2000,
	WRAP_ICMP6_REQUEST	= WRAP_ICMP6|WRAP_REQUEST,
	WRAP_ICMP6_REPLY	= WRAP_ICMP6|WRAP_REPLY,

	WRAP_DNS		= 0x4000,
	WRAP_DNS_REQUEST	= WRAP_DNS|WRAP_REQUEST,
	WRAP_DNS_REPLY		= WRAP_DNS|WRAP_REPLY,

	WRAP_NTP4		= 0x8000,
	WRAP_NTP4_REQUEST	= WRAP_NTP4|WRAP_REQUEST,
	WRAP_NTP4_REPLY		= WRAP_NTP4|WRAP_REPLY,
};


class wrap {

	wrap_t d_how{WRAP_INVALID};
	bool d_mod_mss{0};
	uint16_t d_in_mss{1024}, d_out_mss{1024};

	// last ICMP seq and id field seen on rcv, and for ICMP_ECHO (inside) pkts, the next chosen icmp id
	uint16_t d_last_icmp_seq{0}, d_last_icmp_id{0}, d_next_icmp_seq{0};

	uint8_t d_icmp_type{net_headers::ICMP_ECHO_REQUEST};

	static const uint16_t DIGEST_LEN;
	static const EVP_MD *md;
	static const uint8_t ICMP6_ECHO_MAGIC;

	net_headers::iphdr d_new_iph;
	int d_family{AF_INET}, d_saved_errno{0};
	std::string d_err{""}, d_key{""}, d_domain{""};

	DNS *d_dns{nullptr};

	sockaddr_in d_remote_peer;
	sockaddr_in6 d_remote_peer6;

	std::string icmp_request(const std::string &);

	std::string de_icmp(const std::string &, const sockaddr_in *);

	std::string icmp6_request(const std::string &);

	std::string de_icmp6(const std::string &, const sockaddr_in6 *);

	std::string dns_request(const std::string &);

	std::string de_dns_request(const std::string &, const sockaddr *);

	std::string dns_reply(const std::string &);

	std::string de_dns_reply(const std::string &);

	std::string ntp4(const std::string &);

	std::string de_ntp4(const std::string &, const sockaddr *);

	bool is_wrap_request()
	{
		return (d_how & WRAP_REQUEST) == WRAP_REQUEST;
	}


	bool is_wrap_reply()
	{
		return (d_how & WRAP_REPLY) == WRAP_REPLY;
	}

	int build_error(const std::string &s)
	{
		d_err = "wrap::";
		d_err += s;
		if (errno) {
			d_err += ": ";
			d_err += strerror(errno);
			d_saved_errno = errno;
		}
		return -1;
	}


public:

	wrap(wrap_t w, int af, const std::string &k, const std::string &d = "")
	{
		d_how = w;
		d_family = af;
		d_key = k;
		d_domain = d;

		memset(&d_remote_peer, 0, sizeof(d_remote_peer));
		d_remote_peer.sin_family = AF_INET;
		memset(&d_remote_peer6, 0, sizeof(d_remote_peer6));
		d_remote_peer6.sin6_family = AF_INET6;

	}

	int init(const std::string &, const std::string &, const std::string &, uint16_t, uint8_t);

	void set_family(int f)
	{
		d_family = f;
	}

	void set_mss(uint16_t m1, uint16_t m2)
	{
		d_mod_mss = 1;
		d_in_mss = m1;	// SYN
		d_out_mss = m2;	// SYN+ACK
	}

	void get_dst(struct sockaddr *);

	std::string pack(const std::string &);

	std::string unpack(const std::string &, const sockaddr *);

	// only for DNS
	void adjust_rcv_queue(int);

	// only for DNS
	bool can_respond();

	~wrap()
	{
		delete d_dns;
	}

	const char *why()
	{
		return d_err.c_str();
	}

};

}

#endif

