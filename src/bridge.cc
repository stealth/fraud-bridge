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

#include <unistd.h>
#include <string>
#include <memory>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include "bridge.h"
#include "dns.h"
#include "wrap.h"
#include "misc.h"
#include "net-headers.h"
#include "config.h"


namespace fraudbridge {


using namespace std;


int bridge::init(wrap_t wt, int af, const string &peer, const string &remote, const string &local, const string &d, uint16_t port, uint8_t icmp_type)
{
	d_family = af;
	d_how = wt;
	d_domain = d;

	if ((d_wrapper = new (nothrow) wrap(wt, af, d_key, d_domain)) == nullptr)
		return build_error("init:OOM:");

	int r = 0;
	if ((r = d_wrapper->init(peer, remote, local, port, icmp_type)) < 0)
		return build_error(string("init->") += d_wrapper->why());
	return r;
}


int bridge::forward(int sock, int tap)
{
	if (d_how & WRAP_DNS)
		return forward_dns(sock, tap);
	else if (d_how & WRAP_ICMP)
		return forward_simple(sock, tap);
	else if (d_how & WRAP_ICMP6)
		return forward_simple(sock, tap);
	else if (d_how & WRAP_NTP4)
		return forward_simple(sock, tap);

	return build_error("forward: Invalid wrapper specification.");
}


// for icmp, icmp6 and ntp4
int bridge::forward_simple(int sock, int tap)
{
	if (!d_wrapper)
		return build_error("forward_simple: No wrapper defined");

	uint16_t in_mss = config::mss, out_mss = config::mss;
	d_wrapper->set_mss(in_mss, out_mss);

	int max = sock > tap ? sock : tap;
	int r = -1;
	fd_set rset;

	char buf[4096] = {0};
	string packet = "";
	net_headers::tap_header *th_ptr = nullptr, th = {0, htons(net_headers::ETH_P_IP)};

	sockaddr_in dst4;
	sockaddr_in6 dst6;
	sockaddr *dst = nullptr;
	socklen_t dlen = 0;

	if (d_family == AF_INET) {
		dst = reinterpret_cast<struct sockaddr *>(&dst4);
		dlen = sizeof(dst4);
	} else {
		dst = reinterpret_cast<struct sockaddr *>(&dst6);
		dlen = sizeof(dst6);
	}

	string lprefix = "";
	auto logfunc = [&](const string &dir) {
		if (lprefix.empty()) {
			lprefix = "icmp";
			if (d_how & WRAP_ICMP6)
				lprefix = "icmp6";
			else if (d_how & WRAP_NTP4)
				lprefix = "ntp4";
		}
		log(lprefix + dir + to_string(packet.size()));
	};

	for (;;) {
		FD_ZERO(&rset);
		FD_SET(sock, &rset);
		FD_SET(tap, &rset);

		if ((r = select(max + 1, &rset, nullptr, nullptr, nullptr)) < 0)
			continue;

		if (FD_ISSET(tap, &rset)) {
			if ((r = read(tap, buf, sizeof(buf))) <= 0)
				continue;

			th_ptr = reinterpret_cast<net_headers::tap_header *>(buf);

			if (th_ptr->proto != htons(net_headers::ETH_P_IP))
				continue;

			packet = d_wrapper->pack(string(buf + sizeof(th), r - sizeof(th)));
			d_wrapper->get_dst(dst);

			if (config::verbose && packet.size())
				logfunc(" -> ");

			// ignore errors
			if (packet.size())
				sendto(sock, packet.c_str(), packet.size(), 0, dst, dlen);
		}

		if (FD_ISSET(sock, &rset)) {
			if ((r = recvfrom(sock, buf, sizeof(buf), 0, dst, &dlen)) <= 0)
				continue;

			packet = string(reinterpret_cast<char *>(&th), sizeof(th));
			packet += d_wrapper->unpack(string(buf, r), dst);
			if (packet.size() > sizeof(th)) {
				if (writen(tap, packet.c_str(), packet.size()) <= 0)
					continue;
				if (config::verbose)
					logfunc(" <- ");
			}
		}
	}

	return 0;
}


int bridge::forward_dns(int sock, int tap)
{
	if (!d_wrapper)
		return build_error("forward_dns: No wrapper defined");

	if (d_domain.size() > 100)
		return build_error("forward_dns: Insane large domainname");

	uint16_t in_mss = 0, out_mss = 0;

	// 130 byte payload + max 40byte TCP-hdr + DIGEST (16) *4/3 for b64 encoding + domain size
	in_mss = 130 - d_domain.size();

	if (config::edns0 < 512)
		out_mss = 200;
	else
		out_mss = config::edns0 - 312;

	if (out_mss > 1024)
		out_mss = 1024;

	d_wrapper->set_mss(in_mss, out_mss);

	int max = sock > tap ? sock : tap;
	int r = -1;
	fd_set rset;

	char buf[4096] = {0};
	string packet = "";
	net_headers::tap_header *th_ptr = nullptr, th = {0, htons(net_headers::ETH_P_IP)};
	net_headers::iphdr dummy_hdr;
	dummy_hdr.protocol = IPPROTO_TCP;

	sockaddr_in dst4;
	sockaddr_in6 dst6;
	sockaddr *dst = nullptr;
	socklen_t dlen = 0;

	if (d_family == AF_INET) {
		dst = reinterpret_cast<struct sockaddr *>(&dst4);
		dlen = sizeof(dst4);
	} else {
		dst = reinterpret_cast<struct sockaddr *>(&dst6);
		dlen = sizeof(dst6);
	}

	uint32_t seq = 0;
	struct timeval tv, *tvp = &tv;
	bool did_send = 0;

	d_tx = 0;

	if (d_how == WRAP_DNS_REPLY)
		tvp = nullptr;

	for (;;) {
		FD_ZERO(&rset);
		FD_SET(sock, &rset);
		FD_SET(tap, &rset);

		tv.tv_sec = 0;
		tv.tv_usec = config::useconds;

		// Do not overload DNS server quota
		if (d_how == WRAP_DNS_REQUEST && did_send)
			usleep(config::useconds);
		did_send = 0;

		if ((r = select(max + 1, &rset, nullptr, nullptr, tvp)) < 0)
			continue;

		// If there is a tunnel packet, take it if we can send it out
		// (the do loop saves us from using 'goto')
		do {

		if (FD_ISSET(tap, &rset)) {
			// Do not take packet off tunnel, if we cannot send it out anyways
			if (!d_wrapper->can_respond()) {
				if (config::verbose)
					log("Empty rcv queue");

				// we need a break here since we need to read timer packets
				// from socket if we have empty queue [second FD_ISSET()]
				break;
			}

			if ((r = read(tap, buf, sizeof(buf))) <= 0)
				break;
			th_ptr = reinterpret_cast<net_headers::tap_header *>(buf);

			if (th_ptr->proto != htons(net_headers::ETH_P_IP))
				break;

			packet = d_wrapper->pack(string(buf + sizeof(th), r - sizeof(th)));
			d_wrapper->get_dst(dst);

			if (config::verbose) {
				log("DNS -> " + to_string(packet.size()));
			}

			// ignore errors
			if (packet.size()) {
				d_tx += packet.size();
				sendto(sock, packet.c_str(), packet.size(), 0, dst, dlen);
				did_send = 1;
			}

		// If there is no tunnel packet, answer to last (timer-)request or send timer
		// command request ourself
		} else if (d_wrapper->can_respond()) {
			// need to prepend a dummy IP hdr which is expected and stripped by ->pack()
			memcpy(buf, &dummy_hdr, sizeof(dummy_hdr));
			dns_timer_cmd.nonce = ++seq;
			memcpy(buf + sizeof(dummy_hdr), &dns_timer_cmd, sizeof(dns_timer_cmd));
			packet = d_wrapper->pack(string(buf, sizeof(dummy_hdr) + sizeof(dns_timer_cmd)));
			d_wrapper->get_dst(dst);
			sendto(sock, packet.c_str(), packet.size(), 0, dst, dlen);
			did_send = 1;
			d_tx += packet.size();
		}

		} while (0);


		if (FD_ISSET(sock, &rset)) {
			if ((r = recvfrom(sock, buf, sizeof(buf), 0, dst, &dlen)) <= 0)
				continue;

			packet = string(reinterpret_cast<char *>(&th), sizeof(th));
			packet += d_wrapper->unpack(string(buf, r), dst);
			if (packet.size() > sizeof(th)) {
				if (writen(tap, packet.c_str(), packet.size()) <= 0)
					continue;
				if (config::verbose)
					log("DNS <- " + to_string(packet.size()));
			}
		}

		d_wrapper->adjust_rcv_queue(0);

		// after transmitting X MB of data, give chance to rebind socket
		// for a new local port
		if (d_how == WRAP_DNS_REQUEST && d_tx > config::max_tx)
			break;
	}

	return 0;
}

}

