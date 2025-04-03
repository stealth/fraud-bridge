fraud-bridge
============

<p align="center">
<img src="https://github.com/stealth/fraud-bridge/blob/master/fraud-bridge.jpg" />
</p>


Intro
-----

This project helps bypassing restrictive censorship environments that block
direct TCP or UDP connections, by setting up ICMP, NTP or DNS (over IPv4 or IPv6)
tunnels.

It automatically patches TCP MSS option to achieve a non-fragmented stream of packets (known as MSS-clamping).

It uses MD5 to (HMAC-)integrity protect the tunnel from evil injected TCP packets. If you need privacy,
you have to use encryption yourself. Its assumed that you use SSH over the tunnel anyways.
Either directly or with the SSH proxy option if you need HTTP tunneled.

When DNS tunneling, *fraud-bridge* uses `EDNS0` extension headers to put as many bytes into
the `TXT` reply as possible.

*fraud-bridge* also includes some other techniques to cope with certain *bind* limitations, e.g. quotas/limiting.

Please also note that `c->skills` is providing the full chain of censorship fucking equipment you may be interested in:

[crash](https://github.com/stealth/crash) and [psc](https://github.com/stealth/psc)

You can also use *fraud-bridge* to get full roaming/mobility support into your SSH sessions without any
patch.

Once you have set up the tunnel, you might want to read [how to get your messenger working across the tunnel.](https://github.com/stealth/crash/blob/master/contrib/proxywars.md)

Build
-----

Basically you just do `make` on Linux.

Run
---

The usage is as follows:

```
fraud-bridge -- https://github.com/stealth/fraud-bridge

Usage: fraud-bridge <-k key> [-R IP] [-L IP] [-pP port] [-iIuUnN] [-s sz]
	[-E sz] [-d dev] [-D domain] [-S usec] [-X user] [-r dir] [-t type] [-v]

	-k -- HMAC key to protect tunnel packets
	-R -- IP or IPv6 addr of (outside) peer when started inside
	-L -- local IP addr to bind to if started outside (can be omitted)
	-p -- remote port when in DNS/NTP mode (default: 53/123)
	-P -- local port when in DNS/NTP mode (outside default: 53/123)
	-i -- use ICMP tunnel
	-I -- use ICMPv6 tunnel
	-u -- use DNS tunnel over IP
	-U -- use DNS tunnel over IPv6
	-n -- use NTP4 tunnel over IP
	-N -- use NTP4 tunnel over IPv6
	-E -- set EDNS0 size (default: 1024)
	-s -- set MSS size (default: 1024)
	-d -- tunnel device to use (default: tun1)
	-D -- DNS domain to use when DNS tunneling
	-S -- usec slowdown for DNS ping (default: 5000)
	-X -- user to run as (default: nobody)
	-r -- chroot directory (default: /var/empty)
	-t -- override ICMP/ICMP6 type (usually no need to change)
	-v -- enable verbose mode
```

Some definitions: *inside* refers to the machine inside the censored network,
most likely your laptop/PC. *outside* refers to a VPS or machine outside the
censored network, i.e. what people call "free internet".

After start, *fraud-bridge* opens a point-to-point tunnel: `1.2.3.4` <-> `1.2.3.5`

Then you need to start `inside.sh` on the inside and `outside.sh` outside.

Looks like so:

On outside end of tunnel (e.g. a server at the internet):
```
# ./fraud-bridge -u -L 192.168.2.222 -D f.sub.dnstunnel.com -k key
```
(and starting outside.sh)

And inside:

```
# ./fraud-bridge -u -R 127.0.0.1 -D f.sub.dnstunnel.com -k key
```
(and starting inside.sh)

as an example for a DNS tunnel with a local `127.0.0.1` *named* running and
the outside peer being at `192.168.2.222`. As said, outside part of
tunnel can (and actually needs to) be started beforehand and will just
listen for the peer to open the tunnel. Example zone-files are included if
you want to experiment with your own bind setups. For running ITW tunnels
they are not necessary.

The default tunnel device is `tun1`. Make sure to not run multiple instances of
*fraud-bridge* at the same time or any other tunnel software that is using this
tunnel device. After each kill/restart of *fraud-bridge* daemon you have to execute the
inside/outside scripts again at the particular end where you restarted it.

Important notes
---------------

The `-L` parameter at outside can (should) be omitted. In real setups the `-R` parameter
on inside setups contains the IP or IP6 address of the outside server, or if
DNS recursion is used, the IP address of the DNS server of your provider or
public recursive DNS resolver. If you do not have your own DNS server,
you can still use DNS tunneling by using your VPS IP as `-R` parameter
on inside and using any (but the same) `-D` domain paramater on both ends
that look legit for an censorship regime, e.g. `-D blah.gov`.

**Before trying DNS tunneling, you most likely want to try with ICMP or NTP tunneling.**
If you see `chroot` warnings in the syslog, you can ignore them or provide
valid arguments to `-r`.

You can then use `ssh -D 1234 1.2.3.5` to get a SSH connection to `192.168.2.222`
in above example and use the SOCKS5 proxy on port `:1234` for your web browser session
that then runs across the tunnel.

You can also do that with ICMP: `-i` and ICMP on IPv6: `-I` or DNS on UDP via
IPv6: `-U` or NTP via UDP: `-n` or NTP via UDP/IPv6: `-N`.

It's also possible to switch the kind of tunnel (DNS to ICMP or ICMP to NTP) beyond your SSH connection,
or to roam to another local IP (e.g. switching from wifi to 5G) as the TCP state is kept in local and remote
kernel and not in the bridge. This allows full SSH roaming/mobility support without any patch to SSH.

In verbose mode, *fraud-bridge* will leave `stdout` open for reporting errors or messages,
so you need to run it on a screen or redirect output to `/dev/null` if you need
it running in (verbose) background. Keep that in mind since you need to start the inside/outside
scripts after invoking *fraud-bridge*. If not using `-v`, it goes to background and logs
errors to syslog.

Before using any ICMP tunnels, make sure to relax your cable-modem's firewalling rules
in order to receive the reply packets from your remote peer. *fraud-bridge* works behind
NAT, but it needs to receive the reply packets at last. When using ICMP tunneling and ICMP echos
are blocked, you can set the type parameter via `-t`. For instance using `-t 13` inside and `-t 14`
outside to get timestamp request/reply pairs.

When DNS tunneling, *fraud-bridge* uses `EDNS0` extension headers to put as many bytes into
the `TXT` reply as possible. In my tests, as it tries to answer any timing
packets, it produces no logs in a *bind9* system log-file. If you change
the `EDNS0` (-E), you need to do it on both ends with the same value.
(As inside announces maximum UDP payload size to the nameserver and outside
endpoint calculates the MSS from that what was given with -E.)

When using NTP tunneling, some providers with CGN block large NTP packets (on IPv4 only). In a common german
ISP, any NTP packets > 256 bytes were blocked. So you have to set the MSS accordingly to get smaller packets
like `-s 100` so that the TCP stack is sending the segments in smaller sizes.

Performance considerations
--------------------------

Since *fraud-bridge* opens a PtP tunnel, it can strip the IP header off the packets
that it transmits and synthesize it at each end. So for ICMP tunneling you just have
an overhead of 8 (ICMP) + 16 (HMAC) bytes, which is acceptable. DNS tunneling has still good latency and
bandwidth when doing directly, thanks to MSS clamping. When tunneling indirectly via public
DNS resolvers, the default values are good enough to have a reasonable session, but of course
ICMP tunneling is to prefer whenever possible.

By using `ssh -D [0.0.0.0]:1234 1.2.3.5` you can setup a local SOCKS proxy on your machine
port 1234 (inside) and distribute it via WLAN to your neighborhood for censorship-free web sessions.

You may also setup a local *tor* on the outside box, offering a SOCKS port on `127.0.0.1:9150`
as you normally do and then using `ssh -L 9150:127.0.0.1:9150 1.2.3.5` to forward this outside
port to your inside machine, so to exactly mirror the outside *tor* setup locally and distribute it
as *tor* SOCKS port via WLAN to your users. This way we do not need to implement pluggable transports
and you can still use *tor* as before. The same also works with *crash* or *psc* sessions or any other
tunneling mechanism.

The `-S` parameter has a reasonable default value for the DNS timer packets that need to be sent
to the server in constant interval. Lower values give a better tunnel latency but may overload
the recursive DNS server and produce more noise.


*proudly sponsored by:*
<p align="center">
<a href="https://github.com/c-skills/welcome">
<img src="https://github.com/c-skills/welcome/blob/master/logo.jpg"/>
</a>
</p>

