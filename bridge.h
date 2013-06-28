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

#ifndef __bridge_h__
#define __bridge_h__

#include <string>
#include <cstring>
#include <errno.h>
#include <netinet/in.h>
#include "wrap.h"


class bridge {

	wrap *wrapper;
	wrap_t how;

	std::string err, key, domain;

	int family, saved_errno;

	uint32_t tx;

	int forward_icmp(int, int);

	int forward_dns(int, int);

public:

	bridge(const std::string &k)
		: wrapper(NULL), how(WRAP_INVALID), err(""), key(k),
	          family(AF_INET), saved_errno(0), tx(0)
	{
	}

	~bridge()
	{
		delete wrapper;
	}

	int init(wrap_t w, int, const std::string &, const std::string &, const std::string &,
	         const std::string &d = "");

	int build_error(const std::string &s)
	{
		err = "bridge::";
		err += s;
		if (errno) {
			err += ": ";
			err += strerror(errno);
			saved_errno = errno;
		}
		return -1;
	}

	int forward(int, int);

	const char *why()
	{
		return err.c_str();
	}

	int error()
	{
		return saved_errno;
	}
};

#endif

