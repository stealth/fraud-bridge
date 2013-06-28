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

#include <errno.h>
#include <cstring>
#include <cstdio>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include "tuntap.h"


using namespace std;


int tun_tap::tun_init(const string &dev)
{

	if ((tap_fd = open("/dev/net/tun", O_RDWR)) < 0)
		return build_error("init::open:");

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN;
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev.c_str());
	if (ioctl(tap_fd, TUNSETIFF, &ifr) < 0)
		return build_error("init::ioctl:");

	return 0;
}


int tun_tap::tap_init(const string &dev)
{

	if ((tap_fd = open("/dev/net/tun", O_RDWR)) < 0)
		return build_error("init::open:");

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP;
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev.c_str());
	if (ioctl(tap_fd, TUNSETIFF, &ifr) < 0)
		return build_error("init::ioctl:");

	return 0;
}

