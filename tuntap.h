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

#ifndef __tuntap_h__
#define __tuntap_h__

#include <string>
#include <errno.h>
#include <cstring>


class tun_tap {

	int tap_fd;
	std::string err;

	int build_error(const std::string &msg)
	{
		err = "tun_tap::";
		err += msg;
		err += strerror(errno);
		return -1;
	}

public:

	tun_tap()
	 : tap_fd(-1), err("")
	{
	}


	~tun_tap()
	{
		close(tap_fd);
	}


	int tun_init(const std::string &);

	int tap_init(const std::string &);

	int fd()
	{
		return tap_fd;
	}

	const char *why()
	{
		return err.c_str();
	}
};

#endif

