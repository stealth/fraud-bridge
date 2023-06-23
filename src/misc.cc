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
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cerrno>
#include <syslog.h>
#include <arpa/inet.h>
#include "config.h"
#include "net-headers.h"


namespace fraudbridge {


using namespace std;
using namespace net_headers;


void log(const string &s)
{
	if (config::background) {
		string msg = s;
		if (errno) {
			msg += ": ";
			msg += strerror(errno);
		}
		syslog(LOG_ERR, "%s", msg.c_str());
	} else {
		if (errno)
			fprintf(stderr, "%s: %s\n", s.c_str(), strerror(errno));
		else
			printf("%s\n", s.c_str());
	}
}


void die(const string &s)
{
	log(s);
	exit(errno);
}


int readn(int fd, void *buf, size_t len)
{
	int o = 0, n;
	char *ptr = (char*)buf;

	while (len > 0) {
		if ((n = read(fd, ptr+o, len)) <= 0)
			return n;
		len -= n;
		o += n;
	}
	return o;
}


int writen(int fd, const void *buf, size_t len)
{
	int o = 0, n;
	char *ptr = (char*)buf;

	while (len > 0) {
		if ((n = write(fd, ptr+o, len)) < 0)
			return n;
		len -= n;
		o += n;
	}
	return o;
}


// ripped code, slightly modified
unsigned short in_cksum (const unsigned short *ptr, int nbytes)
{

  long sum;		/* assumes long == 32 bits */
  uint16_t oddbyte;
  uint16_t answer;	/* assumes u_short == 16 bits */

  /*
   * Our algorithm is simple, using a 32-bit accumulator (sum),
   * we add sequential 16-bit words to it, and at the end, fold back
   * all the carry bits from the top 16 bits into the lower 16 bits.
   */

  sum = 0;
  while (nbytes > 1)
    {
      sum += *ptr++;
      nbytes -= 2;
    }

  /* mop up an odd byte, if necessary */
  if (nbytes == 1)
    {
      oddbyte = 0;		/* make sure top half is zero */
      *((unsigned char *) & oddbyte) = *(unsigned char *) ptr;	/* one byte only */
      sum += oddbyte;
    }

  /*
   * Add back carry outs from top 16 bits to low 16 bits.
   */

  sum = (sum >> 16) + (sum & 0xffff);	/* add high-16 to low-16 */
  sum += (sum >> 16);		/* add carry */
  answer = ~sum;		/* ones-complement, then truncate to 16 bits */
  return (answer);
}


void patch_mss(char *packet, char *end_ptr, uint16_t mss)
{
	// We are passed the pointer to TCP options start
	char *tcp_opt = packet;
	bool found_mss = 0, end = 0;

	while (tcp_opt < end_ptr && !end) {
		switch (*tcp_opt) {
		case TCPOPT_EOL:
			end = 1;
			break;
		case TCPOPT_NOP:
			++tcp_opt;
			break;
		case TCPOPT_MAXSEG:
			if (tcp_opt + TCPOLEN_MAXSEG <= packet + sizeof(packet))
				found_mss = 1;
			tcp_opt += 2;
			end = 1;
			break;
		case TCPOPT_WINDOW:
			tcp_opt += TCPOLEN_WINDOW;
			break;
		case TCPOPT_SACK_PERMITTED:
			tcp_opt += TCPOLEN_SACK_PERMITTED;
			break;
		case TCPOPT_TIMESTAMP:
			tcp_opt += TCPOLEN_TIMESTAMP;
			break;
		case TCPOPT_QSR:
			tcp_opt += TCPOLEN_QSR;
			break;
		default:
			end = 1;
		}
	}

	if (found_mss) {
		mss = htons(mss);
		memcpy(tcp_opt, &mss, sizeof(uint16_t));
	}
}


uint16_t ntohs_ua(const void *vp)
{
	uint16_t x = 0;
	memcpy(&x, vp, sizeof(x));
	return ntohs(x);
}


}

