fraud-bridge
============

<p align="center">
<img src="https://github.com/stealth/fraud-bridge/blob/master/fraud-bridge.jpg" />
</p>


Intro
-----

This project helps bypassing restrictive censorship environments that block
direct TCP or UDP connections, by setting up ICMP, ICMP6, DNS or DNS over UDP6
tunnels. It has the same aim as *icmptx*, *iodine*, *ozzyman DNS*, *nstx* etc.

It automatically patches TCP MSS option to achieve a non-fragmented stream
of packets (known as MSS-clamping).

It also uses MD5 to (HMAC-)integrity protect the tunnel
from evil injected TCP packets. If you need privacy, you have to use encryption
yourself. Its assumed that you use SSH over the tunnel anyways.
(Either directly or with the SSH proxy option if you need HTTP tunneled.)

*fraud-bridge* also uses `EDNS0` extension headers to put as many bytes into
the `TXT` reply as possible. In my tests, as it tries to answer any timing
packets, it produces no logs in a *bind9* system log-file. If you change
the `EDNS0` (-E), you need to do it on both ends with the same value.
(As inside announces maximum UDP payload size to the nameserver and outside
endpoint calculates the MSS from that what was given with -E.)

*fraud-bridge* also includes some other techniques to cope with
certain *bind* limitations, e.g. quotas/limiting.

Please also note that `c->skills` is providing the full chain of
censorship fucking equipment you may be interested in:

[crash](https://github.com/stealth/crash) and [psc](https://github.com/stealth/psc)

Build
-----

Basically you just do `make` on Linux.

Run
---

The usage is as follows:

```
fraud-bridge -- https://github.com/stealth/fraud-bridge

Usage: ./src/fraud-bridge <-k key> [-R IP] [-L IP] [-p port] [-i] [-I] [-u] [-U]
	[-E sz] [-d dev] [-D domain] [-S usec] [-X user] [-r dir] [-v]

	-k -- HMAC key to protect tunnel packets
	-R -- IP or IPv6 addr of (outside) peer when started inside
	-L -- local IP addr to bind to if started outside (can be omitted)
	-p -- local port to bind to if in DNS mode (default: 53)
	-i -- use ICMP tunnel
	-I -- use ICMPv6 tunnel
	-u -- use DNS tunnel over IP
	-U -- use DNS tunnel over IPv6
	-E -- set EDNS0 size (default: 1024)
	-d -- tunnel device to use (default: tun1)
	-D -- DNS domain to use when DNS tunneling
	-S -- usec slowdown for DNS ping (default: 5000)
	-X -- user to run as (default: nobody)
	-r -- chroot directory (default: /var/empty)
	-v -- enable verbose mode
```

After start, *fraud-bridge* opens a point-to-point tunnel: `1.2.3.4` <-> `1.2.3.5`

Then you need to start `inside.sh` on the inside and `outside.sh` outside.

Looks like so:

```
# ./fraud-bridge -u -R 127.0.0.1 -D f.sub.dnstunnel.com -k key
```
(and starting inside.sh)

And on outside end of tunnel (e.g. a server at the internet):
```
# ./fraud-bridge -u -L 192.168.2.222 -D f.sub.dnstunnel.com -k key
```
(and starting outside.sh)

for a DNS tunnel with a local `127.0.0.1` *named* running and
the outside peer being at `192.168.2.222`. As said, outside part of
tunnel can (and actually needs to) be started beforehand and will just
listen for the peer to open the tunnel. Example zone-files are included if
you want to experiment with your own bind setups. For running ITW tunnels
they are not necessary.

The `-L` parameter at outside can be omitted. In real setups the `-R` parameter
on inside setups contains the IP or IP6 address of the outside server, or if
DNS recursion is used, the IP address of the DNS server of your provider or
public recursive DNS resolver.

You can then use `ssh -x -v 1.2.3.5` to get a SSH connection to `192.168.2.222`
and use the SSH proxy options to setup a web browser environment that runs
across the tunnel.

You can also do that with ICMP: `-i` and ICMP on IPv6: `-I` or DNS on UDP via
IPv6: `-U`.
It's also possible to switch tunnel from DNS to ICMP beyond your SSH connection,
as the TCP state is kept in local and remote kernel and not in the bridge.

*fraud-bridge* will leave `stdout` open for reporting errors or verbose messages,
so you need to run it on a screen or redirect output to `/dev/null` if you need
it running in background. Keep that in mind since you need to start the inside/outside
scripts after invoking *fraud-bridge*.

Before using any ICMP tunnels, make sure to relax your cable-modem's firewalling rules
in order to receive the reply packets from your remote peer. *fraud-bridge* works behind
NAT, but it needs to receive the reply packets at last.

Performance considerations
--------------------------

Since *fraud-bridge* opens a PtP tunnel, it can strip the IP header off the packets
that it transmits and synthesize it at each end. So for ICMP tunneling you just have
an overhead of 8 bytes, which is neglectable. DNS tunneling has still good latency and
bandwidth when doing directly, thanks to MSS clamping. When tunneling indirectly via public
DNS resolvers, the default values are good enough to have a reasonable session, but of course
ICMP tunneling is to prefer whenever possible.

By using `ssh -D [0.0.0.0]:1234 1.2.3.5` you can setup a local SOCKS proxy on your machine
port 1234 (inside) and distribute it via WLAN to your neighborhood for censorship-free web sessions.


*proudly sponsored by:*
<p align="center">
<a href="https://github.com/c-skills/welcome">
<img src="https://github.com/c-skills/welcome/blob/master/logo.jpg"/>
</a>
</p>

