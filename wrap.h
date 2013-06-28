/*
 * This file is part of fraud-bridge.
 *
 * (C) 2013 by Sebastian Krahmer, sebastian [dot] krahmer [at] gmail [dot] com
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

#ifndef __wrap_h__
#define __wrap_h__

#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include "net-headers.h"
#include "dns.h"


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
};


class wrap {

	wrap_t how;
	bool mod_mss;
	uint16_t in_mss, out_mss;

	static const uint16_t DIGEST_LEN;
	static const EVP_MD *md;
	static const uint8_t ICMP6_ECHO_MAGIC;

	net_headers::iphdr new_iph;
	int family, saved_errno;
	std::string err, key, domain;

	DNS *dns;

	sockaddr_in remote_peer;
	sockaddr_in6 remote_peer6;

	std::string icmp_request(const std::string &);

	std::string icmp_reply(const std::string &);

	std::string icmp_echo(const std::string &, uint8_t);

	std::string de_icmp(const std::string &, const sockaddr_in *);

	std::string icmp6_request(const std::string &);

	std::string icmp6_reply(const std::string &);

	std::string icmp6_echo(const std::string &, uint8_t);

	std::string de_icmp6(const std::string &, const sockaddr_in6 *);

	std::string dns_request(const std::string &);

	std::string de_dns_request(const std::string &, const sockaddr *);

	std::string dns_reply(const std::string &);

	std::string de_dns_reply(const std::string &);


	bool is_wrap_request()
	{
		return (how & WRAP_REQUEST) == WRAP_REQUEST;
	}


	bool is_wrap_reply()
	{
		return (how & WRAP_REPLY) == WRAP_REPLY;
	}

	int build_error(const std::string &s)
	{
		err = "wrap::";
		err += s;
		if (errno) {
			err += ": ";
			err += strerror(errno);
			saved_errno = errno;
		}
		return -1;
	}


public:

	wrap(wrap_t w, int af, const std::string &k, const std::string &d = "")
	{
		err = "";
		how = w;
		mod_mss = 0;
		family = af;
		key = k;
		dns = NULL;
		domain = d;
		saved_errno = 0;

		memset(&remote_peer, 0, sizeof(remote_peer));
		remote_peer.sin_family = AF_INET;
		memset(&remote_peer6, 0, sizeof(remote_peer6));
		remote_peer6.sin6_family = AF_INET6;

	}

	int init(const std::string &, const std::string &, const std::string &);

	void set_family(int f)
	{
		family = f;
	}


	void set_mss(uint16_t m1, uint16_t m2)
	{
		mod_mss = 1;
		in_mss = m1;	// SYN
		out_mss = m2;	// SYN+ACK
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
		delete dns;
	}

	const char *why()
	{
		return err.c_str();
	}

};

#endif
