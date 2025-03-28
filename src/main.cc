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

#define _POSIX_C_SOURCE
#include <cstdio>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include "net-headers.h"
#include "tuntap.h"
#include "wrap.h"
#include "bridge.h"
#include "config.h"
#include "misc.h"


using namespace std;
using namespace fraudbridge;


void usage(const string &path)
{
	printf("Usage: %s <-k key> [-R IP] [-L IP] [-pP port] [-iIuU]\n"
	       "\t[-E sz] [-d dev] [-D domain] [-S usec] [-X user] [-r dir] [-t type] [-v]\n\n"

	       "\t-k -- HMAC key to protect tunnel packets\n"
	       "\t-R -- IP or IPv6 addr of (outside) peer when started inside\n"
	       "\t-L -- local IP addr to bind to if started outside (can be omitted)\n"
	       "\t-p -- remote port when in DNS/NTP mode (default: 53/123)\n"
	       "\t-P -- local port when in DNS/NTP mode (outside default: 53/123)\n"
	       "\t-i -- use ICMP tunnel\n"
	       "\t-I -- use ICMPv6 tunnel\n"
	       "\t-u -- use DNS tunnel over IP\n"
	       "\t-U -- use DNS tunnel over IPv6\n"
	       "\t-n -- use NTP4 tunnel over IP\n"
	       "\t-N -- use NTP4 tunnel over IPv6\n"
	       "\t-E -- set EDNS0 size (default: %d)\n"
	       "\t-d -- tunnel device to use (default: tun1)\n"
	       "\t-D -- DNS domain to use when DNS tunneling\n"
	       "\t-S -- usec slowdown for DNS ping (default: %d)\n"
	       "\t-X -- user to run as (default: nobody)\n"
	       "\t-r -- chroot directory (default: /var/empty)\n"
	       "\t-t -- set ICMP/ICMP6 type (experimental, do not use)\n"
	       "\t-v -- enable verbose mode\n\n", path.c_str(), config::edns0, config::useconds);

	exit(1);
}



int main(int argc, char **argv)
{
	string rhost = "", lhost = "0.0.0.0", rport = "53", lport = "", dev = "tun1", key = "secret",
	       domain = "", user = "nobody", chroot = "/var/empty";
	int sock = 0, type = SOCK_RAW, protocol = IPPROTO_ICMP, r = 0, family = AF_INET;
	wrap_t how = WRAP_INVALID;


	printf("\nfraud-bridge -- https://github.com/stealth/fraud-bridge\n\n");

	string prog = argv[0];

	while ((r = getopt(argc, argv, "iIuUnNR:L:d:k:D:p:P:vE:S:X:r:t:")) != -1) {
		switch (r) {
		case 'S':
			config::useconds = strtoul(optarg, nullptr, 10);
			break;
		case 'E':
			config::edns0 = strtoul(optarg, nullptr, 10);
			break;
		case 'v':
			config::verbose = 1;
			break;
		case 'L':
			lhost = optarg;
			break;
		case 'R':
			rhost = optarg;
			break;
		case 'p':
			rport = optarg;
			break;
		case 'P':
			lport = optarg;
			break;
		case 'i':
			how = WRAP_ICMP;
			break;
		case 'I':
			how = WRAP_ICMP6;
			family = AF_INET6;
			protocol = IPPROTO_ICMPV6;
			break;
		case 'u':
			how = WRAP_DNS;
			type = SOCK_DGRAM;
			protocol = 0;
			break;
		case 'U':
			how = WRAP_DNS;
			type = SOCK_DGRAM;
			family = AF_INET6;
			protocol = 0;
			break;
		case 'n':
			how = WRAP_NTP4;
			type = SOCK_DGRAM;
			family = AF_INET;
			protocol = 0;
			break;
		case 'N':
			how = WRAP_NTP4;
			type = SOCK_DGRAM;
			family = AF_INET6;
			protocol = 0;
			break;
		case 'd':
			dev = optarg;
			break;
		case 'D':
			domain = optarg;
			break;
		case 'k':
			key = optarg;
			break;
		case 'X':
			user = optarg;
			break;
		case 'r':
			chroot = optarg;
			break;
		case 't':
			config::icmp_type = (uint8_t)strtoul(optarg, nullptr, 10);
			break;
		default:
			usage("fraud-bridge");
		}
	}

	if (how == WRAP_INVALID)
		usage(prog);

	if ((how & WRAP_DNS) && !domain.size()) {
		fprintf(stderr, "Requiring domain argument for DNS tunnel.\n\n");
		usage(prog);
	}

	if (key == "secret")
		fprintf(stderr, "Warning: using insecure default HMAC key!\n");

	if (!config::verbose) {
		printf("Going background. Messages will be sent to syslog.\n");
		if (fork() > 0)
			exit(1);

		setsid();

		int fd = open("/dev/null", O_RDWR);
		if (fd < 0)
			die("open(/dev/null)");
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		for (int i = 3; i < 1024; ++i)
			close(i);

		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = SIG_IGN;
		sigaction(SIGPIPE, &sa, nullptr);
		sigaction(SIGCHLD, &sa, nullptr);

		config::background = 1;
		openlog("fraud-bridge", LOG_NOWAIT|LOG_PID|LOG_NDELAY, LOG_USER);
	}

	struct addrinfo *ai = nullptr;

	if (rhost.size())
		how = (wrap_t)(how|WRAP_REQUEST);
	else
		how = (wrap_t)(how|WRAP_REPLY);

	if (how == WRAP_DNS_REPLY && !lport.size())
		lport = "53";
	if (how == WRAP_NTP4_REPLY && !lport.size())
		lport = "123";
	if (how == WRAP_NTP4_REQUEST && rport == "53")
		rport = "123";

	if (family == AF_INET6) {
		if (lhost == "0.0.0.0")
			lhost = "::";
		if (rhost == "")
			rhost = "::";
	} else {
		if (rhost == "")
			rhost = "0.0.0.0";
	}

	if ((r = getaddrinfo(lhost.c_str(), lport.c_str(), nullptr, &ai)) != 0)
		die("getaddrinfo: " + string(gai_strerror(r)));

	tun_tap the_tun;
	the_tun.tun_init(dev);

	bridge the_bridge(key);

	if (how & WRAP_REQUEST) {
		// We do not check for DNS/ICMP. If DNS wrap is used, icmp type will be ignored.
		// icmp type unset?
		if (config::icmp_type == 0) {
			if (family == AF_INET6)
				config::icmp_type = net_headers::ICMP6_ECHO_REQUEST;
			else
				config::icmp_type = net_headers::ICMP_ECHO_REQUEST;
		}
		r = the_bridge.init(how, family, rhost, config::peer2,
		                    config::peer1, domain, strtoul(rport.c_str(), nullptr, 10), config::icmp_type);

	// WRAP_REPLY
	} else {
		// see above
		if (config::icmp_type == 0) {
			if (family == AF_INET6)
				config::icmp_type = net_headers::ICMP6_ECHO_REPLY;
			else
				config::icmp_type = net_headers::ICMP_ECHO_REPLY;
		}
		r = the_bridge.init(how, family, rhost, config::peer1,
		                    config::peer2, domain, strtoul(rport.c_str(), nullptr, 10), config::icmp_type);
	}

	if (r < 0)
		die("Error: " + the_bridge.why());

	passwd *pw = getpwnam(user.c_str());
	if (!pw)
		die("getpwnam");

	if (::chroot(chroot.c_str()) < 0)
		log("Warning: Not possible to chroot!");
	chdir("/");

	if (setgid(pw->pw_gid) < 0)
		die("setgid");
	if (initgroups(user.c_str(), pw->pw_gid) < 0)
		die("initgroups");

	for (;;) {
		if ((sock = socket(family, type, protocol)) < 0)
			die("socket");

		if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0)
			die("bind");

		// bind to port 53 only happens once in WRAP_DNS_REPLY or WRAP_NTP4_REPLY,
		// re-binding is only for WRAP_DNS_REQUEST to unprived port
		if (setuid(pw->pw_uid) < 0)
			die("setuid");

		errno = 0;

		// ignore error
		r = the_bridge.forward(sock, the_tun.fd());
		close(sock);

		if (config::verbose) {
			if (r < 0)
				log("Error: " + the_bridge.why());
			else
				log("Rebinding ...\n");
		}
		errno = 0;
	}

	return -1;
}

