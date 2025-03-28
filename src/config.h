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

#ifndef fraudbridge_config_h
#define fraudbridge_config_h

#include <stdint.h>
#include <string>

namespace config {

	extern bool verbose, background;
	extern uint32_t useconds;
	extern uint16_t edns0;
	extern uint32_t max_tx;
	extern uint8_t icmp_type;
	extern std::string peer1, peer2;
}

#endif

