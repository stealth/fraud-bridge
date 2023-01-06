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

#ifndef fraudbridge_dns_h
#define fraudbridge_dns_h

#include <stdint.h>
#include <time.h>
#include <string>
#include <cstring>
#include <vector>
#include <list>
#include <map>
#include <errno.h>
#include <bits/endian.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "net-headers.h"


namespace fraudbridge {

int host2qname(const std::string&, std::string&);


struct dns_command {
	char op[8];
	uint32_t nonce;
} __attribute__((packed));

extern dns_command dns_timer_cmd;


class DNS {
	// last Queries, so we have a pool of data to which
	// we can respond
	struct a_Q {
		std::string Q_string;
		uint16_t id;
		sockaddr_in peer;
		sockaddr_in6 peer6;
	};

	int sock, family;

	// The domainname used, and its DNS encoded value
	std::string err, domain, enc_domain;
	std::map<addrinfo *, socklen_t> ns_map;

	// last N questions received
	std::list<a_Q> last_Qs;

	// a EDNS0 OPTion, to allow for larger DNS packets than 512 Byte
	struct {
		uint8_t empty_domain;
		uint16_t type, _class;
		uint32_t rcode;
		uint16_t rdlen;
		uint16_t opt_code, opt_len;
	} __attribute__((packed)) EDNS0_RR;

public:
	DNS(int af);

	~DNS();

	const char *why() { return err.c_str(); };

	int build_error(const std::string &s)
	{
		err = "DNS::";
		err += s;
		if (errno) {
			err += ": ";
			err += strerror(errno);
		}
		return -1;
	}

	// Used to check against if tunneling
	void set_domain(const std::string &d)
	{
		domain = d;
		host2qname(domain, enc_domain);
	}

	int query(const std::string&, std::string&, uint16_t qtype = net_headers::dns_type::A);

	int txt_response(const std::string&, std::string&, sockaddr *);

	int parse_query(const std::string&, std::string&, const sockaddr *);

	int parse_txt_response(const std::string&, std::string&);

	int add_ns(const std::string&, const std::string&);

	int send(const std::string&);

	void adjust_Q_list(int);

	void trunc_Q_list(int);

	bool can_respond();
};

}

#endif

