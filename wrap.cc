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

#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "wrap.h"
#include "misc.h"
#include "base64.h"
#include "dns.h"
#include "net-headers.h"


namespace fraudbridge {


using namespace std;
using namespace net_headers;


const uint16_t wrap::DIGEST_LEN = 16;
const EVP_MD *wrap::md = EVP_md5();

// if id field is used, it must be uint16_t
const uint8_t wrap::ICMP6_ECHO_MAGIC = 0x73;


string wrap::icmp_request(const string &data)
{
	return icmp_echo(data, ICMP_ECHO_REQUEST);
}


string wrap::icmp_reply(const string &data)
{
	return icmp_echo(data, ICMP_ECHO_REPLY);
}


string wrap::icmp_echo(const string &data, uint8_t type)
{
	string result = "";
	const iphdr *iph = reinterpret_cast<const iphdr *>(data.c_str());

	if ((uint16_t)(iph->ihl<<2) >= data.size() || iph->protocol != IPPROTO_TCP || data.size() > 4096)
		return result;

	const tcphdr *tcph = reinterpret_cast<const tcphdr *>(data.c_str() + (iph->ihl<<2));

	icmphdr icmph, *icmphp = nullptr;
	memset(&icmph, 0, sizeof(icmph));
	icmph.type = type;

	if (is_wrap_reply()) {
		icmph.un.echo.sequence = d_last_icmp_seq;
		icmph.un.echo.id = d_last_icmp_id;
	} else {
		icmph.un.echo.sequence = htons(d_next_icmp_seq++);
		icmph.un.echo.id = 0;
	}

	const size_t psize = sizeof(icmph) + DIGEST_LEN + data.size() - (iph->ihl<<2);
	char *packet = new (nothrow) char[psize];
	if (!packet)
		return result;
	memcpy(packet, &icmph, sizeof(icmph));
	memcpy(packet + sizeof(icmph) + DIGEST_LEN, tcph, data.size() - (iph->ihl<<2));

	// compute MD5 HMAC
	unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
	HMAC(md, d_key.c_str(), (int)d_key.size(), (unsigned char *)packet + sizeof(icmph) + DIGEST_LEN,
	     psize - sizeof(icmph) - DIGEST_LEN, hmac, nullptr);
	memcpy(packet + sizeof(icmph), hmac, DIGEST_LEN);

	icmphp = reinterpret_cast<icmphdr *>(packet);
	icmphp->sum = in_cksum((unsigned short *)packet, psize);

	result.assign(packet, psize);

	delete [] packet;
	return result;
}



string wrap::de_icmp(const string &data, const sockaddr_in *from)
{
	string result = "";

	const iphdr *iph = reinterpret_cast<const iphdr *>(data.c_str());

	if (data.size() < sizeof(icmphdr) + sizeof(tcphdr) + (iph->ihl<<2) + DIGEST_LEN ||
	    data.size() > 4096)
		return result;

	// first, check MD5 HMAC
	unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
	HMAC(md, d_key.c_str(), (int)d_key.size(),
	     (unsigned char *)data.c_str() + (iph->ihl<<2) + sizeof(icmphdr) + DIGEST_LEN,
	     data.size() - (iph->ihl<<2) - sizeof(icmphdr) - DIGEST_LEN, hmac, nullptr);
	if (memcmp(data.c_str() + (iph->ihl<<2) + sizeof(icmphdr), hmac, DIGEST_LEN) != 0)
		return result;

	const icmphdr *icmph = reinterpret_cast<const icmphdr *>(data.c_str() + (iph->ihl<<2));
	d_last_icmp_seq = icmph->un.echo.sequence;
	d_last_icmp_id = icmph->un.echo.id;

	const uint16_t psize = data.size() - sizeof(icmphdr) - DIGEST_LEN + sizeof(d_new_iph) - (iph->ihl<<2);
	char *packet = new (nothrow) char[psize];
	if (!packet)
		return result;
	memcpy(packet + sizeof(d_new_iph), data.c_str() + (iph->ihl<<2) + sizeof(icmphdr) + DIGEST_LEN,
	       data.size() - (iph->ihl<<2) - sizeof(icmphdr) - DIGEST_LEN);

	pseudohdr ph;
	memset(&ph, 0, sizeof(ph));
	ph.saddr = d_new_iph.saddr;
	ph.daddr = d_new_iph.daddr;
	ph.proto = IPPROTO_TCP;
	ph.len = htons((uint16_t)data.size() - (iph->ihl<<2) - sizeof(icmphdr) - DIGEST_LEN);

	memcpy(packet + sizeof(d_new_iph) - sizeof(ph), &ph, sizeof(ph));
	tcphdr *tcph = reinterpret_cast<tcphdr *>(packet + sizeof(d_new_iph));

	// patch MSS, which is announced during SYN/SYN|ACK
	if (tcph->th_flags & TH_SYN) {
		// outside tunnel endpoint is decapsulating what comes from inside, so patch in
		// max outgoing MSS; and vice versa
		if (is_wrap_reply())
			patch_mss(packet + sizeof(d_new_iph) + sizeof(tcphdr), packet + psize, d_out_mss);
		else
			patch_mss(packet + sizeof(d_new_iph) + sizeof(tcphdr), packet + psize, d_in_mss);
	}

	tcph->th_sum = 0;
	tcph->th_sum = in_cksum((unsigned short *)(packet + sizeof(d_new_iph) - sizeof(ph)),
	                        sizeof(ph) + ntohs(ph.len));

	memcpy(packet, &d_new_iph, sizeof(d_new_iph));

	iphdr *d_new_iph_ptr = (iphdr *)packet;
	d_new_iph_ptr->tot_len = htons(psize);
	d_new_iph_ptr->check = in_cksum((unsigned short *)packet, sizeof(d_new_iph));

	// no need to set remote peer on tunnel endpoint inside, which is using -R
	if (is_wrap_reply())
		d_remote_peer = *from;

	result.assign(packet, psize);
	delete [] packet;
	return result;
}


string wrap::icmp6_echo(const string &data, uint8_t type)
{
	string result = "";

	// still an IPv4 header, comes via tun
	const iphdr *iph = reinterpret_cast<const iphdr *>(data.c_str());

	if ((uint16_t)(iph->ihl<<2) >= data.size() || iph->protocol != IPPROTO_TCP)
		return result;

	const tcphdr *tcph = reinterpret_cast<const tcphdr *>(data.c_str() + (iph->ihl<<2));

	icmp6_hdr icmph, *icmphp = nullptr;
	memset(&icmph, 0, sizeof(icmph));
	icmph.icmp6_type = type;

	// Need to set a special ID field in reply, as theres AFAIK no good way to
	// prevent kernel from replying to icmp6 echo requests itself. So we need it to quickly
	// filter response on arrival
	if (is_wrap_reply()) {
		icmph.icmp6_code = ICMP6_ECHO_MAGIC;

		//if code is checked by FW, use this (id field)
		//icmph.icmp6_dataun.icmp6_un_data16[0] = htons(ICMP6_ECHO_MAGIC);

		icmph.icmp6_dataun.icmp6_un_data16[1] = d_last_icmp_seq;
	} else
		icmph.icmp6_dataun.icmp6_un_data16[1] = htons(d_next_icmp_seq++);

	const size_t psize = sizeof(icmph) + DIGEST_LEN + data.size() - (iph->ihl<<2);
	char *packet = new (nothrow) char[psize];
	if (!packet)
		return result;
	memcpy(packet, &icmph, sizeof(icmph));
	memcpy(packet + sizeof(icmph) + DIGEST_LEN, tcph, data.size() - (iph->ihl<<2));

	// compute MD5 HMAC
	unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
	HMAC(md, d_key.c_str(), (int)d_key.size(), (unsigned char *)packet + sizeof(icmph) + DIGEST_LEN,
	     psize - sizeof(icmph) - DIGEST_LEN, hmac, nullptr);
	memcpy(packet + sizeof(icmph), hmac, DIGEST_LEN);

	icmphp = reinterpret_cast<icmp6_hdr *>(packet);
	icmphp->icmp6_cksum = in_cksum((unsigned short *)packet, psize);

	result.assign(packet, psize);
	return result;
}


string wrap::icmp6_request(const string &data)
{
	return icmp6_echo(data, ICMP6_ECHO_REQUEST);
}


string wrap::icmp6_reply(const string &data)
{
	return icmp6_echo(data, ICMP6_ECHO_REPLY);
}


string wrap::de_icmp6(const string &data, const sockaddr_in6 *from6)
{
	string result = "";

	if (data.size() < sizeof(icmp6_hdr) + sizeof(tcphdr) + DIGEST_LEN || data.size() > 4096)
		return result;

	const icmp6_hdr *icmph = reinterpret_cast<const icmp6_hdr *>(data.c_str());

	// replies must contain magic to distinguish between tunnel answers and kernel icmp replies
	//if (how == WRAP_ICMP6_REQUEST && icmph->icmp6_dataun.icmp6_un_data16[0] != htons(ICMP6_ECHO_MAGIC))
	if (is_wrap_request() && icmph->icmp6_code != ICMP6_ECHO_MAGIC)
		return result;

	// first, check MD5 HMAC
	unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
	HMAC(md, d_key.c_str(), (int)d_key.size(),
	     (unsigned char *)data.c_str() + sizeof(icmp6_hdr) + DIGEST_LEN,
	     data.size() - sizeof(icmphdr) - DIGEST_LEN, hmac, nullptr);
	if (memcmp(data.c_str() + sizeof(icmp6_hdr), hmac, DIGEST_LEN) != 0)
		return result;

	d_last_icmp_seq = icmph->icmp6_dataun.icmp6_un_data16[1];

	const uint16_t psize = data.size() - sizeof(icmp6_hdr) - DIGEST_LEN + sizeof(d_new_iph);
	char *packet = new (nothrow) char[psize];
	if (!packet)
		return result;
	memcpy(packet + sizeof(d_new_iph), data.c_str() + sizeof(icmp6_hdr) + DIGEST_LEN,
	       data.size() - sizeof(icmp6_hdr) - DIGEST_LEN);

	pseudohdr ph;
	memset(&ph, 0, sizeof(ph));
	ph.saddr = d_new_iph.saddr;
	ph.daddr = d_new_iph.daddr;
	ph.proto = IPPROTO_TCP;
	ph.len = htons((uint16_t)data.size() - sizeof(icmp6_hdr) - DIGEST_LEN);

	memcpy(packet + sizeof(d_new_iph) - sizeof(ph), &ph, sizeof(ph));
	tcphdr *tcph = (tcphdr *)(packet + sizeof(d_new_iph));

	// patch MSS, which is announced during SYN/SYN|ACK
	if (tcph->th_flags & TH_SYN) {
		// outside tunnel endpoint is decapsulating what comes from inside, so patch in
		// max outgoing MSS; and vice versa
		if (is_wrap_reply())
			patch_mss(packet + sizeof(d_new_iph) + sizeof(tcphdr), packet + psize, d_out_mss);
		else
			patch_mss(packet + sizeof(d_new_iph) + sizeof(tcphdr), packet + psize, d_in_mss);
	}

	tcph->th_sum = 0;
	tcph->th_sum = in_cksum((unsigned short *)(packet + sizeof(d_new_iph) - sizeof(ph)),
	                        sizeof(ph) + ntohs(ph.len));

	memcpy(packet, &d_new_iph, sizeof(d_new_iph));

	iphdr *d_new_iph_ptr = (iphdr *)packet;
	d_new_iph_ptr->tot_len = htons(psize);
	d_new_iph_ptr->check = in_cksum((unsigned short *)packet, sizeof(d_new_iph));

	if (is_wrap_reply())
		d_remote_peer6 = *from6;

	result.assign(packet, psize);
	delete [] packet;
	return result;
}


string wrap::dns_request(const string &data)
{
	string result = "";
	const iphdr *iph = reinterpret_cast<const iphdr *>(data.c_str());

	if ((uint16_t)(iph->ihl<<2) >= data.size() || iph->protocol != IPPROTO_TCP || data.size() > 4096)
		return result;

	const tcphdr *tcph = reinterpret_cast<const tcphdr *>(data.c_str() + (iph->ihl<<2));

	const size_t psize = DIGEST_LEN + data.size() - (iph->ihl<<2);
	char *packet = new (nothrow) char[psize];
	if (!packet)
		return result;
	memcpy(packet + DIGEST_LEN, tcph, data.size() - (iph->ihl<<2));

	// compute MD5 HMAC
	unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
	HMAC(md, d_key.c_str(), (int)d_key.size(), (unsigned char *)packet + DIGEST_LEN,
	     psize - DIGEST_LEN, hmac, nullptr);
	memcpy(packet, hmac, DIGEST_LEN);

	string b64 = "";
	b64_encode(string(packet, psize), b64);
	b64 += "." + d_domain;

	delete [] packet;

	d_dns->query(b64, result, dns_type::TXT);

	return result;
}


string wrap::dns_reply(const string &data)
{
	string result = "", tmp = "";
	const iphdr *iph = reinterpret_cast<const iphdr *>(data.c_str());

	if ((uint16_t)(iph->ihl<<2) >= data.size() || iph->protocol != IPPROTO_TCP)
		return result;

	const tcphdr *tcph = reinterpret_cast<const tcphdr *>(data.c_str() + (iph->ihl<<2));

	const size_t psize = DIGEST_LEN + data.size() - (iph->ihl<<2);
	char *packet = new (nothrow) char[psize];
	if (!packet)
		return result;
	memcpy(packet + DIGEST_LEN, tcph, data.size() - (iph->ihl<<2));

	// compute MD5 HMAC
	unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
	HMAC(md, d_key.c_str(), (int)d_key.size(), (unsigned char *)packet + DIGEST_LEN,
	     psize - DIGEST_LEN, hmac, nullptr);
	memcpy(packet, hmac, DIGEST_LEN);

	sockaddr_in dst;
	sockaddr_in6 dst6;
	sockaddr *to = reinterpret_cast<sockaddr *>(&dst);
	if (d_family == AF_INET6)
		to = reinterpret_cast<sockaddr *>(&dst6);

	if (d_dns->txt_response(string(packet, psize), tmp, to) < 0)
		return result;
	delete [] packet;

	if (d_family == AF_INET)
		memcpy(&d_remote_peer, to, sizeof(d_remote_peer));
	else
		memcpy(&d_remote_peer6, to, sizeof(d_remote_peer6));

	result = tmp;
	return result;
}


string wrap::de_dns_request(const string &data, const sockaddr *from)
{
	string result = "", tmp = "";

	if (data.size() < sizeof(dnshdr) || data.size() > 4096)
		return result;

	if (d_dns->parse_query(data, tmp, from) < 0)
		return result;

	if (tmp.size() < DIGEST_LEN + sizeof(dns_timer_cmd))
		return result;

	unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
	HMAC(md, d_key.c_str(), (int)d_key.size(), (unsigned char *)tmp.c_str() + DIGEST_LEN,
	     tmp.size() - DIGEST_LEN, hmac, nullptr);

	// On HMAC failure, need to remove last saved sender from internal queue
	if (memcmp(tmp.c_str(), hmac, DIGEST_LEN) != 0) {
		d_dns->trunc_Q_list(1);
		return result;
	}

	// instead of TCP hdr, we might have a timer command (dont cmp nonce)
	if (memcmp(tmp.c_str() + DIGEST_LEN, &dns_timer_cmd,
	           sizeof(dns_timer_cmd) - sizeof(uint32_t)) == 0)
		return result;

	if (tmp.size() < DIGEST_LEN + sizeof(tcphdr))
		return result;

	const uint16_t psize = tmp.size() - DIGEST_LEN + sizeof(d_new_iph);
	char *packet = new (nothrow) char[psize];
	if (!packet)
		return result;
	memcpy(packet + sizeof(d_new_iph), tmp.c_str() + DIGEST_LEN,
	       tmp.size() - DIGEST_LEN);

	pseudohdr ph;
	memset(&ph, 0, sizeof(ph));
	ph.saddr = d_new_iph.saddr;
	ph.daddr = d_new_iph.daddr;
	ph.proto = IPPROTO_TCP;
	ph.len = htons((uint16_t)tmp.size() - DIGEST_LEN);

	memcpy(packet + sizeof(d_new_iph) - sizeof(ph), &ph, sizeof(ph));
	tcphdr *tcph = reinterpret_cast<tcphdr *>(packet + sizeof(d_new_iph));

	// patch MSS, which is negotiated during SYN/SYN|ACK
	if (tcph->th_flags & TH_SYN) {
		// outside tunnel endpoint is decapsulating what comes from inside, so patch in
		// max outgoing MSS; and vice versa
		if (is_wrap_reply())
			patch_mss(packet + sizeof(d_new_iph) + sizeof(tcphdr), packet + psize, d_out_mss);
		else
			patch_mss(packet + sizeof(d_new_iph) + sizeof(tcphdr), packet + psize, d_in_mss);
	}

	tcph->th_sum = 0;
	tcph->th_sum = in_cksum((unsigned short *)(packet + sizeof(d_new_iph) - sizeof(ph)),
	                        sizeof(ph) + ntohs(ph.len));

	memcpy(packet, &d_new_iph, sizeof(d_new_iph));

	iphdr *d_new_iph_ptr = (iphdr *)packet;
	d_new_iph_ptr->tot_len = htons(psize);
	d_new_iph_ptr->check = in_cksum((unsigned short *)packet, sizeof(d_new_iph));


	result.assign(packet, psize);
	delete [] packet;
	return result;
}


string wrap::de_dns_reply(const string &data)
{
	string result = "", tmp = "";

	if (d_dns->parse_txt_response(data, tmp) < 0)
		return result;

	// timer responses will automagically be dropped here too
	if (tmp.size() < DIGEST_LEN + sizeof(tcphdr))
		return result;

	unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
	HMAC(md, d_key.c_str(), (int)d_key.size(), (unsigned char *)tmp.c_str() + DIGEST_LEN,
	     tmp.size() - DIGEST_LEN, hmac, nullptr);
	if (memcmp(tmp.c_str(), hmac, DIGEST_LEN) != 0)
		return tmp;

	const uint16_t psize = tmp.size() - DIGEST_LEN + sizeof(d_new_iph);
	char *packet = new (nothrow) char[psize];
	memcpy(packet + sizeof(d_new_iph), tmp.c_str() + DIGEST_LEN,
	       tmp.size() - DIGEST_LEN);

	pseudohdr ph;
	memset(&ph, 0, sizeof(ph));
	ph.saddr = d_new_iph.saddr;
	ph.daddr = d_new_iph.daddr;
	ph.proto = IPPROTO_TCP;
	ph.len = htons((uint16_t)tmp.size() - DIGEST_LEN);

	memcpy(packet + sizeof(d_new_iph) - sizeof(ph), &ph, sizeof(ph));
	tcphdr *tcph = reinterpret_cast<tcphdr *>(packet + sizeof(d_new_iph));

	// patch MSS, which is announced during SYN/SYN|ACK
	if (tcph->th_flags & TH_SYN) {
		// outside tunnel endpoint is decapsulating what comes from inside, so patch in
		// max outgoing MSS; and vice versa
		if (is_wrap_reply())
			patch_mss(packet + sizeof(d_new_iph) + sizeof(tcphdr), packet + psize, d_out_mss);
		else
			patch_mss(packet + sizeof(d_new_iph) + sizeof(tcphdr), packet + psize, d_in_mss);
	}

	tcph->th_sum = 0;
	tcph->th_sum = in_cksum((unsigned short *)(packet + sizeof(d_new_iph) - sizeof(ph)),
	                        sizeof(ph) + ntohs(ph.len));

	memcpy(packet, &d_new_iph, sizeof(d_new_iph));

	iphdr *d_new_iph_ptr = (iphdr *)packet;
	d_new_iph_ptr->tot_len = htons(psize);
	d_new_iph_ptr->check = in_cksum((unsigned short *)packet, sizeof(d_new_iph));

	result.assign(packet, psize);
	delete [] packet;
	return result;
}


// remote is the IP4 of the remote tun interface (src of prepended IP hdr, so
// that replies arrive back on tun), local is the local IP of tun (which is a p-to-p intf)
int wrap::init(const string &peer, const string &remote, const string &local)
{
	in_addr ia1, ia2;

	// always AF_INET, as we use IP4 internally on tun
	if (inet_pton(AF_INET, remote.c_str(), &ia1) != 1)
		return build_error("init::inet_pton");

	if (inet_pton(AF_INET, local.c_str(), &ia2) != 1)
		return build_error("init::inet_pton");

	if (d_family == AF_INET) {
		if (inet_pton(d_family, peer.c_str(), &d_remote_peer.sin_addr) != 1)
			return build_error("init::inet_pton");
	} else {
		if (inet_pton(d_family, peer.c_str(), &d_remote_peer6.sin6_addr) != 1)
			return build_error("init::inet_pton");
	}

	d_new_iph.daddr = ia2.s_addr;
	d_new_iph.saddr = ia1.s_addr;

	d_new_iph.protocol = IPPROTO_TCP;

	if (d_how & WRAP_DNS) {
		if ((d_dns = new (nothrow) DNS(d_family)) == nullptr)
			return build_error("init::OOM");

		d_dns->set_domain(d_domain);

		if (d_how & WRAP_REQUEST) {
			d_remote_peer.sin_port = htons(53);
			d_remote_peer6.sin6_port = htons(53);
		}
	}

	return 0;
}


string wrap::pack(const string &data)
{
	string s = "";

	switch (d_how) {
	case WRAP_ICMP_REQUEST:
		s = icmp_request(data);
		break;
	case WRAP_ICMP_REPLY:
		s = icmp_reply(data);
		break;
	case WRAP_ICMP6_REQUEST:
		s = icmp6_request(data);
		break;
	case WRAP_ICMP6_REPLY:
		s = icmp6_reply(data);
		break;
	case WRAP_DNS_REQUEST:
		s = dns_request(data);
		break;
	case WRAP_DNS_REPLY:
		s = dns_reply(data);
		break;
	default:
		;
	}

	return s;
}


string wrap::unpack(const string &data, const sockaddr *saddr)
{
	string s = "";

	switch (d_how) {
	case WRAP_ICMP_REQUEST:
	case WRAP_ICMP_REPLY:
		s = de_icmp(data, reinterpret_cast<const sockaddr_in *>(saddr));
		break;
	case WRAP_ICMP6_REQUEST:
	case WRAP_ICMP6_REPLY:
		s = de_icmp6(data, reinterpret_cast<const sockaddr_in6 *>(saddr));
		break;
	case WRAP_DNS_REQUEST:
		s = de_dns_reply(data);
		break;
	case WRAP_DNS_REPLY:
		s = de_dns_request(data, saddr);
		break;
	default:
		;
	}
	return s;
}


bool wrap::can_respond()
{
	if (!d_dns)
		return 1;

	if (d_how == WRAP_DNS_REPLY)
		return d_dns->can_respond();

	return 1;
}

// return next valid destination for a tunnel reply
void wrap::get_dst(struct sockaddr *sa)
{
	if (d_family == AF_INET) {
		memcpy(sa, &d_remote_peer, sizeof(d_remote_peer));
	} else {
		memcpy(sa, &d_remote_peer6, sizeof(d_remote_peer6));
	}
}


// remove old DNS timer requests from queue
void wrap::adjust_rcv_queue(int i)
{
	if (!d_dns)
		return;

	d_dns->adjust_Q_list(i);
}

}


