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

#ifndef fraudbridge_misc_h
#define fraudbridge_misc_h

#include <cstdint>
#include <string>


namespace fraudbridge {

void log(const std::string &);

void die(const std::string &);

int writen(int, const void *, size_t);

int readn(int, void *, size_t);

unsigned short in_cksum (const unsigned short *, int);

void patch_mss(char *, char *, uint16_t);

uint16_t ntohs_ua(const void *);


}

#endif

