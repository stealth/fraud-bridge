/*
 * This file is part of fraud-bridge.
 *
 * (C) 2013-2023 by Sebastian Krahmer, sebastian [dot] krahmer [at] gmail [dot] com
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

#ifndef fraudbridge_bridge_h
#define fraudbridge_bridge_h

#include <string>
#include <cstring>
#include <cerrno>
#include <netinet/in.h>
#include "wrap.h"


namespace fraudbridge {


class bridge {

	wrap *d_wrapper{nullptr};
	wrap_t d_how{WRAP_INVALID};

	std::string d_err{""}, d_key{""}, d_domain{""};

	int d_family{AF_INET}, d_saved_errno{0};

	uint32_t d_tx{0};

	int forward_icmp(int, int);

	int forward_dns(int, int);

	int forward_ntp4(int, int);

public:

	bridge(const std::string &k)
		: d_key(k)
	{
	}

	~bridge()
	{
		delete d_wrapper;
	}

	int init(wrap_t w, int, const std::string &, const std::string &, const std::string &, const std::string &, uint16_t, uint8_t);

	int build_error(const std::string &s)
	{
		d_err = "bridge::";
		d_err += s;
		if (errno) {
			d_err += ": ";
			d_err += strerror(errno);
			d_saved_errno = errno;
		}
		return -1;
	}

	int forward(int, int);

	std::string why()
	{
		return d_err;
	}

	int error()
	{
		return d_saved_errno;
	}
};


}

#endif

