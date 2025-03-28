/*
 * This file is part of fraud-bridge.
 *
 * (C) 2013-2025 by Sebastian Krahmer
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
#include <memory>
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


// The function name is a bit misleading: it also wraps ICMP replies
string wrap::icmp_request(const string &data)
{
	string result = "";
	const iphdr *iph = reinterpret_cast<const iphdr *>(data.c_str());

	if ((uint16_t)(iph->ihl<<2) >= data.size() || iph->protocol != IPPROTO_TCP || data.size() > 4096)
		return result;

	const tcphdr *tcph = reinterpret_cast<const tcphdr *>(data.c_str() + (iph->ihl<<2));

	icmphdr icmph = {0}, *icmphp = nullptr;
	icmph.type = d_icmp_type;

	if (is_wrap_reply()) {
		icmph.un.echo.sequence = d_last_icmp_seq;
		icmph.un.echo.id = d_last_icmp_id;
	} else {
		icmph.un.echo.sequence = htons(d_next_icmp_seq++);
		icmph.un.echo.id = 0;
	}

	const size_t psize = sizeof(icmph) + DIGEST_LEN + data.size() - (iph->ihl<<2);
	unique_ptr<char[]> packet(new (nothrow) char[psize]);
	if (!packet.get())
		return result;
	memcpy(packet.get(), &icmph, sizeof(icmph));
	memcpy(packet.get() + sizeof(icmph) + DIGEST_LEN, tcph, data.size() - (iph->ihl<<2));

	// compute MD5 HMAC
	unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
	HMAC(md, d_key.c_str(), (int)d_key.size(),
	     reinterpret_cast<unsigned char *>(packet.get() + sizeof(icmph) + DIGEST_LEN),
	     psize - sizeof(icmph) - DIGEST_LEN, hmac, nullptr);
	memcpy(packet.get() + sizeof(icmph), hmac, DIGEST_LEN);

	icmphp = reinterpret_cast<icmphdr *>(packet.get());
	icmphp->sum = in_cksum(reinterpret_cast<unsigned short *>(packet.get()), psize);

	result.assign(packet.get(), psize);

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
	     reinterpret_cast<const unsigned char *>(data.c_str() + (iph->ihl<<2) + sizeof(icmphdr) + DIGEST_LEN),
	     data.size() - (iph->ihl<<2) - sizeof(icmphdr) - DIGEST_LEN, hmac, nullptr);
	if (memcmp(data.c_str() + (iph->ihl<<2) + sizeof(icmphdr), hmac, DIGEST_LEN) != 0)
		return result;

	const icmphdr *icmph = reinterpret_cast<const icmphdr *>(data.c_str() + (iph->ihl<<2));
	d_last_icmp_seq = icmph->un.echo.sequence;
	d_last_icmp_id = icmph->un.echo.id;

	const uint16_t psize = data.size() - sizeof(icmphdr) - DIGEST_LEN + sizeof(d_new_iph) - (iph->ihl<<2);
	unique_ptr<char[]> packet(new (nothrow) char[psize]);
	if (!packet.get())
		return result;
	memcpy(packet.get() + sizeof(d_new_iph), data.c_str() + (iph->ihl<<2) + sizeof(icmphdr) + DIGEST_LEN,
	       data.size() - (iph->ihl<<2) - sizeof(icmphdr) - DIGEST_LEN);

	pseudohdr ph = {0};
	ph.saddr = d_new_iph.saddr;
	ph.daddr = d_new_iph.daddr;
	ph.proto = IPPROTO_TCP;
	ph.len = htons((uint16_t)data.size() - (iph->ihl<<2) - sizeof(icmphdr) - DIGEST_LEN);

	memcpy(packet.get() + sizeof(d_new_iph) - sizeof(ph), &ph, sizeof(ph));
	tcphdr *tcph = reinterpret_cast<tcphdr *>(packet.get() + sizeof(d_new_iph));

	// patch MSS, which is announced during SYN/SYN|ACK
	if (tcph->th_flags & TH_SYN) {
		// outside tunnel endpoint is decapsulating what comes from inside, so patch in
		// max outgoing MSS; and vice versa
		if (is_wrap_reply())
			patch_mss(packet.get() + sizeof(d_new_iph) + sizeof(tcphdr), packet.get() + psize, d_out_mss);
		else
			patch_mss(packet.get() + sizeof(d_new_iph) + sizeof(tcphdr), packet.get() + psize, d_in_mss);
	}

	tcph->th_sum = 0;
	tcph->th_sum = in_cksum(reinterpret_cast<unsigned short *>(packet.get() + sizeof(d_new_iph) - sizeof(ph)),
	                        sizeof(ph) + ntohs(ph.len));

	memcpy(packet.get(), &d_new_iph, sizeof(d_new_iph));

	iphdr *d_new_iph_ptr = reinterpret_cast<iphdr *>(packet.get());
	d_new_iph_ptr->tot_len = htons(psize);
	d_new_iph_ptr->check = in_cksum(reinterpret_cast<unsigned short *>(packet.get()), sizeof(d_new_iph));

	// no need to set remote peer on tunnel endpoint inside, which is using -R
	if (is_wrap_reply())
		d_remote_peer = *from;

	result.assign(packet.get(), psize);
	return result;
}


string wrap::icmp6_request(const string &data)
{
	string result = "";

	// still an IPv4 header, comes via tun
	const iphdr *iph = reinterpret_cast<const iphdr *>(data.c_str());

	if ((uint16_t)(iph->ihl<<2) >= data.size() || iph->protocol != IPPROTO_TCP)
		return result;

	const tcphdr *tcph = reinterpret_cast<const tcphdr *>(data.c_str() + (iph->ihl<<2));

	icmp6_hdr icmph = {0}, *icmphp = nullptr;
	icmph.icmp6_type = d_icmp_type;

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
	unique_ptr<char[]> packet(new (nothrow) char[psize]);
	if (!packet.get())
		return result;
	memcpy(packet.get(), &icmph, sizeof(icmph));
	memcpy(packet.get() + sizeof(icmph) + DIGEST_LEN, tcph, data.size() - (iph->ihl<<2));

	// compute MD5 HMAC
	unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
	HMAC(md, d_key.c_str(), (int)d_key.size(),
	     reinterpret_cast<unsigned char *>(packet.get() + sizeof(icmph) + DIGEST_LEN),
	     psize - sizeof(icmph) - DIGEST_LEN, hmac, nullptr);
	memcpy(packet.get() + sizeof(icmph), hmac, DIGEST_LEN);

	icmphp = reinterpret_cast<icmp6_hdr *>(packet.get());
	icmphp->icmp6_cksum = in_cksum(reinterpret_cast<unsigned short *>(packet.get()), psize);

	result.assign(packet.get(), psize);
	return result;
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
	     reinterpret_cast<const unsigned char *>(data.c_str() + sizeof(icmp6_hdr) + DIGEST_LEN),
	     data.size() - sizeof(icmp6_hdr) - DIGEST_LEN, hmac, nullptr);
	if (memcmp(data.c_str() + sizeof(icmp6_hdr), hmac, DIGEST_LEN) != 0)
		return result;

	d_last_icmp_seq = icmph->icmp6_dataun.icmp6_un_data16[1];

	const uint16_t psize = data.size() - sizeof(icmp6_hdr) - DIGEST_LEN + sizeof(d_new_iph);
	unique_ptr<char[]> packet(new (nothrow) char[psize]);
	if (!packet.get())
		return result;
	memcpy(packet.get() + sizeof(d_new_iph), data.c_str() + sizeof(icmp6_hdr) + DIGEST_LEN,
	       data.size() - sizeof(icmp6_hdr) - DIGEST_LEN);

	pseudohdr ph;
	memset(&ph, 0, sizeof(ph));
	ph.saddr = d_new_iph.saddr;
	ph.daddr = d_new_iph.daddr;
	ph.proto = IPPROTO_TCP;
	ph.len = htons((uint16_t)data.size() - sizeof(icmp6_hdr) - DIGEST_LEN);

	memcpy(packet.get() + sizeof(d_new_iph) - sizeof(ph), &ph, sizeof(ph));
	tcphdr *tcph = reinterpret_cast<tcphdr *>(packet.get() + sizeof(d_new_iph));

	// patch MSS, which is announced during SYN/SYN|ACK
	if (tcph->th_flags & TH_SYN) {
		// outside tunnel endpoint is decapsulating what comes from inside, so patch in
		// max outgoing MSS; and vice versa
		if (is_wrap_reply())
			patch_mss(packet.get() + sizeof(d_new_iph) + sizeof(tcphdr), packet.get() + psize, d_out_mss);
		else
			patch_mss(packet.get() + sizeof(d_new_iph) + sizeof(tcphdr), packet.get() + psize, d_in_mss);
	}

	tcph->th_sum = 0;
	tcph->th_sum = in_cksum(reinterpret_cast<unsigned short *>(packet.get() + sizeof(d_new_iph) - sizeof(ph)),
	                        sizeof(ph) + ntohs(ph.len));

	memcpy(packet.get(), &d_new_iph, sizeof(d_new_iph));

	iphdr *d_new_iph_ptr = reinterpret_cast<iphdr *>(packet.get());
	d_new_iph_ptr->tot_len = htons(psize);
	d_new_iph_ptr->check = in_cksum(reinterpret_cast<unsigned short *>(packet.get()), sizeof(d_new_iph));

	if (is_wrap_reply())
		d_remote_peer6 = *from6;

	result.assign(packet.get(), psize);
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
	unique_ptr<char[]> packet(new (nothrow) char[psize]);
	if (!packet.get())
		return result;
	memcpy(packet.get() + DIGEST_LEN, tcph, data.size() - (iph->ihl<<2));

	// compute MD5 HMAC
	unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
	HMAC(md, d_key.c_str(), (int)d_key.size(),
	     reinterpret_cast<unsigned char *>(packet.get() + DIGEST_LEN),
	     psize - DIGEST_LEN, hmac, nullptr);
	memcpy(packet.get(), hmac, DIGEST_LEN);

	string b64 = "";
	b64_encode(string(packet.get(), psize), b64);
	b64 += "." + d_domain;

	packet.reset(nullptr);

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
	unique_ptr<char[]> packet(new (nothrow) char[psize]);
	if (!packet.get())
		return result;
	memcpy(packet.get() + DIGEST_LEN, tcph, data.size() - (iph->ihl<<2));

	// compute MD5 HMAC
	unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
	HMAC(md, d_key.c_str(), (int)d_key.size(),
	     reinterpret_cast<unsigned char *>(packet.get() + DIGEST_LEN),
	     psize - DIGEST_LEN, hmac, nullptr);
	memcpy(packet.get(), hmac, DIGEST_LEN);

	sockaddr_in dst;
	sockaddr_in6 dst6;
	sockaddr *to = reinterpret_cast<sockaddr *>(&dst);
	if (d_family == AF_INET6)
		to = reinterpret_cast<sockaddr *>(&dst6);

	if (d_dns->txt_response(string(packet.get(), psize), tmp, to) < 0)
		return result;

	packet.reset(nullptr);

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
	HMAC(md, d_key.c_str(), (int)d_key.size(),
	     reinterpret_cast<const unsigned char *>(tmp.c_str() + DIGEST_LEN),
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
	unique_ptr<char[]> packet(new (nothrow) char[psize]);
	if (!packet.get())
		return result;
	memcpy(packet.get() + sizeof(d_new_iph), tmp.c_str() + DIGEST_LEN,
	       tmp.size() - DIGEST_LEN);

	pseudohdr ph;
	memset(&ph, 0, sizeof(ph));
	ph.saddr = d_new_iph.saddr;
	ph.daddr = d_new_iph.daddr;
	ph.proto = IPPROTO_TCP;
	ph.len = htons((uint16_t)tmp.size() - DIGEST_LEN);

	memcpy(packet.get() + sizeof(d_new_iph) - sizeof(ph), &ph, sizeof(ph));
	tcphdr *tcph = reinterpret_cast<tcphdr *>(packet.get() + sizeof(d_new_iph));

	// patch MSS, which is negotiated during SYN/SYN|ACK
	if (tcph->th_flags & TH_SYN) {
		// outside tunnel endpoint is decapsulating what comes from inside, so patch in
		// max outgoing MSS; and vice versa
		if (is_wrap_reply())
			patch_mss(packet.get() + sizeof(d_new_iph) + sizeof(tcphdr), packet.get() + psize, d_out_mss);
		else
			patch_mss(packet.get() + sizeof(d_new_iph) + sizeof(tcphdr), packet.get() + psize, d_in_mss);
	}

	tcph->th_sum = 0;
	tcph->th_sum = in_cksum(reinterpret_cast<unsigned short *>(packet.get() + sizeof(d_new_iph) - sizeof(ph)),
	                        sizeof(ph) + ntohs(ph.len));

	memcpy(packet.get(), &d_new_iph, sizeof(d_new_iph));

	iphdr *d_new_iph_ptr = reinterpret_cast<iphdr *>(packet.get());
	d_new_iph_ptr->tot_len = htons(psize);
	d_new_iph_ptr->check = in_cksum(reinterpret_cast<unsigned short *>(packet.get()), sizeof(d_new_iph));


	result.assign(packet.get(), psize);
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
	HMAC(md, d_key.c_str(), (int)d_key.size(),
	     reinterpret_cast<const unsigned char *>(tmp.c_str() + DIGEST_LEN),
	     tmp.size() - DIGEST_LEN, hmac, nullptr);
	if (memcmp(tmp.c_str(), hmac, DIGEST_LEN) != 0)
		return tmp;

	const uint16_t psize = tmp.size() - DIGEST_LEN + sizeof(d_new_iph);
	unique_ptr<char[]> packet(new (nothrow) char[psize]);
	if (!packet.get())
		return tmp;

	memcpy(packet.get() + sizeof(d_new_iph), tmp.c_str() + DIGEST_LEN,
	       tmp.size() - DIGEST_LEN);

	pseudohdr ph;
	memset(&ph, 0, sizeof(ph));
	ph.saddr = d_new_iph.saddr;
	ph.daddr = d_new_iph.daddr;
	ph.proto = IPPROTO_TCP;
	ph.len = htons((uint16_t)tmp.size() - DIGEST_LEN);

	memcpy(packet.get() + sizeof(d_new_iph) - sizeof(ph), &ph, sizeof(ph));
	tcphdr *tcph = reinterpret_cast<tcphdr *>(packet.get() + sizeof(d_new_iph));

	// patch MSS, which is announced during SYN/SYN|ACK
	if (tcph->th_flags & TH_SYN) {
		// outside tunnel endpoint is decapsulating what comes from inside, so patch in
		// max outgoing MSS; and vice versa
		if (is_wrap_reply())
			patch_mss(packet.get() + sizeof(d_new_iph) + sizeof(tcphdr), packet.get() + psize, d_out_mss);
		else
			patch_mss(packet.get() + sizeof(d_new_iph) + sizeof(tcphdr), packet.get() + psize, d_in_mss);
	}

	tcph->th_sum = 0;
	tcph->th_sum = in_cksum(reinterpret_cast<unsigned short *>(packet.get() + sizeof(d_new_iph) - sizeof(ph)),
	                        sizeof(ph) + ntohs(ph.len));

	memcpy(packet.get(), &d_new_iph, sizeof(d_new_iph));

	iphdr *d_new_iph_ptr = reinterpret_cast<iphdr *>(packet.get());
	d_new_iph_ptr->tot_len = htons(psize);
	d_new_iph_ptr->check = in_cksum(reinterpret_cast<unsigned short *>(packet.get()), sizeof(d_new_iph));

	result.assign(packet.get(), psize);
	return result;
}


string wrap::ntp4(const string &data)
{
	string result = "";
	const iphdr *iph = reinterpret_cast<const iphdr *>(data.c_str());

	if ((uint16_t)(iph->ihl<<2) >= data.size() || iph->protocol != IPPROTO_TCP || data.size() > 4096)
		return result;

	const tcphdr *tcph = reinterpret_cast<const tcphdr *>(data.c_str() + (iph->ihl<<2));

	ntp4hdr ntph;
	ntp4exthdr ntpeh;

	if (is_wrap_reply()) {
		ntph.mode = MODE_SERVER;
	} else {
		ntph.mode = MODE_CLIENT;
	}

	ntpeh.length = htons(data.size() - (iph->ihl<<2));

	// unlike ICMP, the MD5 is calculated over ntphdr + data and appended to the end, as
	// NTP4 protocol has a field (after extensions) for it anyways, so we are going to use it
	uint32_t mac_id = 0, pad = 0;

	size_t psize = sizeof(ntph) + sizeof(ntpeh) + data.size() - (iph->ihl<<2) + sizeof(pad) + sizeof(mac_id) + DIGEST_LEN;
	unique_ptr<char[]> packet(new (nothrow) char[psize]);
	if (!packet.get())
		return result;
	memcpy(packet.get(), &ntph, sizeof(ntph));
	memcpy(packet.get() + sizeof(ntph), &ntpeh, sizeof(ntpeh));
	memcpy(packet.get() + sizeof(ntph) + sizeof(ntpeh), tcph, data.size() - (iph->ihl<<2));

	// add padding to NTP4 32bit boundary
	auto pidx = sizeof(ntph) + sizeof(ntpeh) + data.size() - (iph->ihl<<2);
	for (; ((pidx + pad) % sizeof(uint32_t)) != 0; ++pad)
		;
	psize -= sizeof(pad);
	psize += pad;

	// compute MD5 HMAC
	unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
	HMAC(md, d_key.c_str(), (int)d_key.size(),
	     reinterpret_cast<unsigned char *>(packet.get()),
	     psize - sizeof(mac_id) - DIGEST_LEN, hmac, nullptr);

	memcpy(packet.get() + psize - sizeof(mac_id) - DIGEST_LEN, &mac_id, sizeof(mac_id));
	memcpy(packet.get() + psize - DIGEST_LEN, hmac, DIGEST_LEN);

	result.assign(packet.get(), psize);

	return result;
}



string wrap::de_ntp4(const string &data, const sockaddr *from)
{
	string result = "";

	uint32_t mac_id = 0;

	if (data.size() < sizeof(ntp4hdr) + sizeof(ntp4exthdr) + sizeof(tcphdr) + sizeof(mac_id) + DIGEST_LEN ||
	    data.size() > 4096)
		return result;

	// first, check MD5 HMAC
	unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
	HMAC(md, d_key.c_str(), (int)d_key.size(),
	     reinterpret_cast<const unsigned char *>(data.c_str()), data.size() - sizeof(mac_id) - DIGEST_LEN, hmac, nullptr);

	if (memcmp(data.c_str() + data.size() - DIGEST_LEN, hmac, DIGEST_LEN) != 0)
		return result;

	const ntp4hdr *ntph = reinterpret_cast<const ntp4hdr *>(data.c_str());
	const ntp4exthdr *ntpeh = reinterpret_cast<const ntp4exthdr *>(ntph + 1);


	uint16_t psize = ntohs(ntpeh->length);
	if (psize > 4096 || psize < sizeof(tcphdr))
		return result;

	// but psize w/o alignment, so no exact match
	if (psize > (data.size() - sizeof(ntp4hdr) - sizeof(ntp4exthdr) - sizeof(mac_id) - DIGEST_LEN))
		return result;
	psize += sizeof(d_new_iph);
	unique_ptr<char[]> packet(new (nothrow) char[psize]);
	if (!packet.get())
		return result;

	memcpy(packet.get() + sizeof(d_new_iph), data.c_str() + sizeof(ntp4hdr) + sizeof(ntp4exthdr), psize - sizeof(d_new_iph));

	pseudohdr ph = {0};
	ph.saddr = d_new_iph.saddr;
	ph.daddr = d_new_iph.daddr;
	ph.proto = IPPROTO_TCP;
	ph.len = ntpeh->length;		// already htons()

	memcpy(packet.get() + sizeof(d_new_iph) - sizeof(ph), &ph, sizeof(ph));
	tcphdr *tcph = reinterpret_cast<tcphdr *>(packet.get() + sizeof(d_new_iph));

	// patch MSS, which is announced during SYN/SYN|ACK
	if (tcph->th_flags & TH_SYN) {
		// outside tunnel endpoint is decapsulating what comes from inside, so patch in
		// max outgoing MSS; and vice versa
		if (is_wrap_reply())
			patch_mss(packet.get() + sizeof(d_new_iph) + sizeof(tcphdr), packet.get() + psize, d_out_mss);
		else
			patch_mss(packet.get() + sizeof(d_new_iph) + sizeof(tcphdr), packet.get() + psize, d_in_mss);
	}

	tcph->th_sum = 0;
	tcph->th_sum = in_cksum(reinterpret_cast<unsigned short *>(packet.get() + sizeof(d_new_iph) - sizeof(ph)),
	                        sizeof(ph) + ntohs(ntpeh->length));

	memcpy(packet.get(), &d_new_iph, sizeof(d_new_iph));

	iphdr *d_new_iph_ptr = reinterpret_cast<iphdr *>(packet.get());
	d_new_iph_ptr->tot_len = htons(psize);
	d_new_iph_ptr->check = in_cksum(reinterpret_cast<unsigned short *>(packet.get()), sizeof(d_new_iph));

	// no need to set remote peer on tunnel endpoint inside, which is using -R
	if (is_wrap_reply()) {
		if (d_family == AF_INET)
			memcpy(&d_remote_peer, reinterpret_cast<const sockaddr_in *>(from), sizeof(sockaddr_in));
		else
			memcpy(&d_remote_peer6, reinterpret_cast<const sockaddr_in6* >(from), sizeof(sockaddr_in6));
	}

	result.assign(packet.get(), psize);
	return result;
}


// remote is the IP4 of the remote tun interface (src of prepended IP hdr, so
// that replies arrive back on tun), local is the local IP of tun (which is a p-to-p intf)
int wrap::init(const string &peer, const string &remote, const string &local, uint16_t udp_port, uint8_t icmp_request_type)
{
	d_icmp_type = icmp_request_type;

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

		if (udp_port == 0)
			udp_port = 53;

		if (d_how & WRAP_REQUEST) {
			d_remote_peer.sin_port = htons(udp_port);
			d_remote_peer6.sin6_port = htons(udp_port);
		}
	} else if (d_how & WRAP_NTP4) {
		if (udp_port == 0)
			udp_port = 123;

		if (d_how & WRAP_REQUEST) {
			d_remote_peer.sin_port = htons(udp_port);
			d_remote_peer6.sin6_port = htons(udp_port);
		}
	}

	return 0;
}


string wrap::pack(const string &data)
{
	string s = "";

	switch (d_how) {

	// Icmp request and reply packet construction are the same, except the type code that
	// is set in the icmp hdr. The type code however is set during bridge::init() when the caller
	// knows whether its the inside or outside part of the bridge and sets type to be ICMP_ECHO_REQUEST or
	// _REPLY accordingly. So, when being here the d_icmp_type is already set correctly.
	case WRAP_ICMP_REQUEST:
	case WRAP_ICMP_REPLY:
		s = icmp_request(data);
		break;
	case WRAP_ICMP6_REQUEST:
	case WRAP_ICMP6_REPLY:
		s = icmp6_request(data);
		break;
	case WRAP_DNS_REQUEST:
		s = dns_request(data);
		break;
	case WRAP_DNS_REPLY:
		s = dns_reply(data);
		break;

	// similar to icmp, the difference is just one bit
	case WRAP_NTP4_REQUEST:
	case WRAP_NTP4_REPLY:
		s = ntp4(data);
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
	case WRAP_NTP4_REQUEST:
	case WRAP_NTP4_REPLY:
		s = de_ntp4(data, saddr);
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


