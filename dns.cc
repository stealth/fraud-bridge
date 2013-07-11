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

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <map>
#include <vector>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "base64.h"
#include "dns.h"
#include "config.h"


using namespace std;
using namespace net_headers;


const uint8_t dns_max_label = 63;
dns_command dns_timer_cmd = {
	{'T', 'I', 'M', 'E', 'R', 0, 0, 0},
	0xffffffff
};


bool sockaddrLess::operator()(sockaddr s1, sockaddr s2)
{
	return memcmp(&s1, &s2, sizeof(s1)) < 0;
}

/*  "\003foo\003bar\000" -> foo.bar
 */
int qname2host(const string &msg, string &result)
{
	string::size_type i = 0;
	uint8_t len = 0;

	result = "";
	string s = "";
	try {
		s.reserve(msg.length());
	} catch (...) {
		return -1;
	}

	while ((len = msg[i]) != 0) {
		if (len > dns_max_label)
			return -1;
		if (len + i + 1 > msg.size())
			return -1;
		s += msg.substr(i + 1, len);
		s += ".";
		i += len + 1;
	}
	result = s;
	return i + 1;
}


/*  "\003foo\003bar\02ab\02de\0", "\02ab\02de\0"-> foobar.ab.de
 * (to unsplit the automatically splitted large labels from host2qname())
 * Un-splitting of domains stops if encoded_domain is seen
 */
int qname2host(const string &msg, string &result, const string &encoded_domain)
{
	string::size_type i = 0;
	uint8_t len = 0;
	bool add_dot = 0;

	result = "";
	string s = "";

	try {
		s.reserve(msg.length());
	} catch (...) {
		return -1;
	}

	while ((len = msg[i]) != 0) {
		if (len > dns_max_label)
			return -1;
		if (len + i + 1 > msg.size())
			return -1;

		if (add_dot)
			s += ".";
		s += msg.substr(i + 1, len);
		i += len + 1;
		if (encoded_domain == msg.substr(i, encoded_domain.size()))
			add_dot = 1;
	}
	result = s;
	return i + 1;
}


/* "foo.bar" -> "\003foo\003bar\000"
 * automatically splits labels larger than 63 byte into
 * sub-domains
 */
int host2qname(const string &host, string &result)
{
	string split_host = "";
	string::size_type pos1 = 0, pos2 = 0;

	for (;pos1 < host.size();) {
		pos2 = host.find(".", pos1);
		if (pos2 == string::npos) {
			split_host += host.substr(pos1);
			break;
		}

		if (pos2 - pos1 > dns_max_label) {
			split_host += host.substr(pos1, dns_max_label);
			pos1 += dns_max_label;
		} else {
			split_host += host.substr(pos1, pos2 - pos1);
			pos1 = pos2 + 1;
		}

		split_host += ".";
	}

	try {
		result.clear();
		result.reserve(split_host.length() + 2);
		result.resize(split_host.length() + 2);
	} catch (...) {
		return -1;
	}

	int i = 0, j = 0, k = 0, l = 0;
	uint8_t how_much = 0;

	while (i < (int)split_host.length()) {
		l = i;
		how_much = 0;
		while (split_host[i] != '.' && i != (int)split_host.length()) {
			++how_much;
			++i;
		}
		result[j] = how_much;
		++j;
		i = l;
		for (k = 0; k < how_much; j++, i++, k++)
			result[j] = split_host[i];
		++i;
	}
	result[j] = '\0';
	return j + 1;
}


int DNS::query(const string &host, string &result, uint16_t qtype)
{
	static uint16_t seq = 0;
	err = "";
	result = "";
	string qname = "";

	dnshdr dnsh;
	memset(&dnsh, 0, sizeof(dnsh));
	dnsh.id = ++seq;
	dnsh.rd = 1;
	dnsh.q_count = htons(1);
	if (config::edns0)
		dnsh.ad_count = htons(1);	// EDNS0 OPT RR

	size_t buflen = sizeof(dnsh) + 2*sizeof(uint16_t);
	if (host2qname(host, qname) < 0)
		return build_error("query: cannot encode hostname");
	buflen += qname.length();

	if (config::edns0)
		buflen += sizeof(EDNS0_RR);

	char *buf = new (nothrow) char[buflen];
	if (!buf)
		return build_error("query: OOM");

	memcpy(buf, &dnsh, sizeof(dnsh));
	size_t idx = sizeof(dnsh);

	memcpy(buf + idx, qname.c_str(), qname.size());
	idx += qname.size();
	*(uint16_t *)&buf[idx] = htons(qtype);
	idx += sizeof(uint16_t);
	*(uint16_t *)&buf[idx] =  htons(1); // INET
	idx += sizeof(uint16_t);

	if (config::edns0)
		memcpy(buf + idx, &EDNS0_RR, sizeof(EDNS0_RR));

	result.assign(buf, buflen);
	delete [] buf;
	return 0;
}


DNS::DNS(int af)
{
	family = af;
	sock = -1;
	err = "";

	memset(&EDNS0_RR, 0, sizeof(EDNS0_RR));
	EDNS0_RR.type = htons(dns_type::OPT);
	EDNS0_RR._class = htons(config::edns0);
}


DNS::~DNS()
{
	if (sock > 0)
		close(sock);
}


int DNS::add_ns(const string &host, const string &port = "53")
{
	err = "";
	struct addrinfo *ai = NULL, hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_DGRAM;

 	int e;
	if ((e = getaddrinfo(host.c_str(), port.c_str(), &hints, &ai)) < 0) {
		err = "DNS::add_ns:getaddrinfo:";
		err += gai_strerror(e);
		return -1;
	}

	ns_map[*(ai->ai_addr)] = ai->ai_addrlen;
	freeaddrinfo(ai);
	return 0;
}

// Turn the b64 encoded hostname inside an A query into the
// Layer2 packet and also save from where the query was sent
int DNS::parse_query(const string &msg, string &packet, const sockaddr *from)
{
	packet = "";
	if (msg.size() < sizeof(dnshdr) + 4 + 6)
		return -1;

	const dnshdr *hdr = (const dnshdr *)msg.c_str();
	const char *qname = msg.c_str() + sizeof(dnshdr);

	if (ntohs(hdr->q_count) != 1)
		return build_error("parse_query: q_count != 1");

	string fqdn = "";
	int nl = 0;

	// automatically joins large labels
	if ((nl = qname2host(string(qname, msg.size() - sizeof(dnshdr)), fqdn, enc_domain)) < 0)
		return -1;

	if (sizeof(dnshdr) + nl + 4 > msg.size() || fqdn.find(domain) == string::npos)
		return build_error("parse_query: Invalid query (1)");
	string::size_type domain_start = 0;
	if ((domain_start = fqdn.find("." + domain)) == string::npos)
		return build_error("parse_query: Invalid query (2)");

	b64_decode(fqdn.substr(0, domain_start), packet);

	if (!packet.size())
		return build_error("parse_query: Invalid query (3)");

	a_Q Q;

	Q.Q_string = string(qname, nl + 4);
	Q.id = hdr->id;

	if (family == AF_INET)
		Q.peer = *reinterpret_cast<const sockaddr_in *>(from);
	else
		Q.peer6 = *reinterpret_cast<const sockaddr_in6 *>(from);

	last_Qs.push_back(Q);

	return 0;
}


int DNS::txt_response(const string &msg, string &result, sockaddr *to)
{
	char buf[0x1000];

	result = "";

	if (last_Qs.size() == 0)
		return build_error("txt_response: Q list empty");

	a_Q Q = last_Qs.front();
	last_Qs.pop_front();

	if (Q.Q_string.size() > 256 || Q.Q_string.size() < 8 || msg.size() > 1500)
		return build_error("txt_response: invalid Q entry or msg size");

	memset(buf, 0, sizeof(buf));

	dnshdr hdr;
	hdr.id = Q.id;
	hdr.qr = 1;
	hdr.aa = 1;
	hdr.ra = 1;
	hdr.q_count = htons(1);
	hdr.a_count = htons(1);
	if (config::edns0)
		hdr.ad_count = htons(1);	// EDNS0 OPT RR

	uint16_t cl = htons(1), type = htons(dns_type::TXT), rdlen = 0;
	uint32_t ttl = 0;
	uint16_t *rdlen_ptr = NULL;
	int idx = 0;
	uint8_t l = 0;
	memcpy(buf, &hdr, sizeof(hdr)); idx = sizeof(hdr);
	memcpy(buf + idx, Q.Q_string.c_str(), Q.Q_string.size()); idx += Q.Q_string.size();

	// TXT answer RR (full name, but we use compressed label)
	// [memcpy(buf + idx, Q.Q_string.c_str(), Q.Q_string.size() - 4); idx += Q.Q_string.size() - 4;]

	// same name in answer as found in Q section
	uint16_t compressed_lbl = htons(((1<<15)|(1<<14))|sizeof(dnshdr));
	memcpy(buf + idx, &compressed_lbl, sizeof(compressed_lbl)); idx += sizeof(compressed_lbl);
	memcpy(buf + idx, &type, sizeof(type)); idx += sizeof(type);
	memcpy(buf + idx, &cl, sizeof(cl)); idx += sizeof(cl);
	memcpy(buf + idx, &ttl, sizeof(ttl)); idx += sizeof(ttl);

	memcpy(buf + idx, &rdlen, sizeof(rdlen));
	rdlen_ptr = (uint16_t *)(buf + idx); idx += sizeof(rdlen);

	for (string::size_type i = 0; i < msg.size();) {
		if (msg.size() - i > 0xff)
			l = 0xff;
		else
			l = msg.size() - i;

		rdlen += (l + 1);

		buf[idx] = l; ++idx;
		memcpy(buf + idx, msg.c_str() + i, l);
		idx += l;
		i += l;
	}

	*rdlen_ptr = htons(rdlen);

	// EDNS0 OPT RR to slip through large packets
	if (config::edns0) {
		memcpy(buf + idx, &EDNS0_RR, sizeof(EDNS0_RR));
		idx += sizeof(EDNS0_RR);
	}

	result = string(buf, idx);

	if (family == AF_INET)
		memcpy(to, &Q.peer, sizeof(Q.peer));
	else
		memcpy(to, &Q.peer6, sizeof(Q.peer6));

	return 0;
}


int DNS::parse_txt_response(const string &msg, string &packet)
{
	packet = "";
	if (msg.size() < sizeof(dnshdr) + 4 + 16)
		return build_error("parse_txt_response: TXT response too short");

	const dnshdr *hdr = (const dnshdr *)msg.c_str();
	const char *qname = msg.c_str() + sizeof(dnshdr);

	if (ntohs(hdr->q_count) != 1 || hdr->rcode != 0)
		return build_error("parse_txt_response: invalid packet (1)");

	string fqdn = "";
	int nl = 0;	// length of DNS encoded name
	if ((nl = qname2host(string(qname, msg.size() - sizeof(dnshdr)), fqdn, enc_domain)) < 0)
		return build_error("parse_txt_response: invalid packet (2)");
	if (fqdn.find(domain) == string::npos || nl >= 0x1000 || nl <= 0)
		return build_error("parse_txt_response: invalid packet (3)");
	const uint16_t *type_ptr = NULL, *rdlen_ptr = NULL;
	uint8_t olen = 0;

	// points behind question section
	const char *idx = (const char *)(msg.c_str() + sizeof(dnshdr) + nl + 2*sizeof(uint16_t));
	const char *txt_rr = NULL;
	string s = "";

	for (uint16_t i = 0; i < ntohs(hdr->a_count); ++i) {
		// compressed label?
		if ((uint8_t)idx[0] > dns_max_label)
			idx += 2;
		else
			idx += nl;
		if (idx + 5*sizeof(uint16_t) > msg.c_str() + msg.size())
			return build_error("parse_txt_response: invalid packet (4)");
		type_ptr = (const uint16_t *)idx;
		rdlen_ptr = (const uint16_t *)(type_ptr + 4);	// 4 16bit words

		if (ntohs(*type_ptr) != dns_type::TXT)
			return build_error("parse_txt_response: invalid packet (5)");
		if (ntohs(*rdlen_ptr) == 0)
			return build_error("parse_txt_response: invalid packet (6)");
		txt_rr = (const char *)(rdlen_ptr + 1);

		if (txt_rr + ntohs(*rdlen_ptr) > msg.c_str() + msg.size())
			return build_error("parse_txt_response: invalid packet (7)");

		const char *txt_octets = txt_rr;

		// decode one or more octect strings inside the TXT RDATA field
		for (uint16_t j = 0; j < ntohs(*rdlen_ptr);) {
			if ((olen = txt_octets[0]) == 0)
				break;
			if (txt_octets + 1 + olen > txt_rr + ntohs(*rdlen_ptr))
				return build_error("parse_txt_response: invalid packet (8)");;
			s += string(txt_octets + 1, olen);
			txt_octets += olen + 1;
			j += olen + 1;
		}
		idx += ntohs(*rdlen_ptr);
	}

	packet = s;
	if (packet.size() == 0)
		return -1;
	return 0;
}



int DNS::send(const string &msg)
{
	if (sock < 0) {
		if ((sock = socket(family, SOCK_DGRAM, 0)) < 0)
			return build_error("send::socket");
	}

	for (map<sockaddr, uint16_t>::iterator i = ns_map.begin(); i != ns_map.end(); ++i)
		sendto(sock, msg.c_str(), msg.length(), 0, &(i->first), i->second);
	return 0;
}


void DNS::adjust_Q_list(int i)
{
	while (last_Qs.size() > 3)
		last_Qs.pop_front();

	while (last_Qs.size() > 0 && i--)
		last_Qs.pop_front();
}


void DNS::trunc_Q_list(int i)
{
	while (last_Qs.size() > 0 && i--)
		last_Qs.pop_back();
}


bool DNS::can_respond()
{
	return last_Qs.size() > 0;
}

