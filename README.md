fraud-bridge
============

<p align="center">
<img src="https://github.com/stealth/fraud-bridge/blob/master/fraud-bridge.jpg" />
</p>


Intro
-----

This project helps bypassing restrictive censorship environments that block
direct TCP or UDP connections, by setting up ICMP, ICMP6, DNS or DNS over UDP6
tunnels. It has the same aim as icmptx, iodine, ozzyman DNS, nstx etc.

It automatically patches TCP MSS option to achieve a non-fragmented stream
of packets (known as MSS-clamping).

It also uses MD5 to (HMAC-)integrity protect the tunnel
from evil injected TCP packets. If you need privacy, you have to use encryption
yourself. Its assumed that you use SSH over the tunnel anyways.
(Either directly or with the SSH proxy option if you need HTTP tunneld.)

*fraud-bridge* also uses `EDNS0` extension headers to put as many bytes into
the `TXT` reply as possible. In my tests, as it tries to answer any timing
packets, it produces no logs in a bind9 system logfile. If you change
the `EDNS0` (-E), you need to do it on both ends with the same value.
(As inside announces maximum UDP payload size to the nameserver and outside
endpoint calculates the MSS from that what was given with -E.)

*fraud-bridge* also includes some other techniques to cope with
certain *bind* limitations, e.g. quotas/limiting.

Please also note that `c->skills` is providing the full chain of
censorship fucking equipment you may be interested in:


[crash](https://github.com/stealth/crash)
[psc](https://github.com/stealth/psc)


Build
-----

Basically you just do `make` on Linux.


Run
---

After start, it opens a point-to-point tunnel: `1.2.3.4` <-> `1.2.3.5`

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

for a DNS tunnel with a local (127.0.0.1) named running and
the outside peer being at 192.168.2.222. As said, outside part of
tunnel can (and actually needs to) be started beforehand and will just
listen for the peer to open the tunnel. Example zonefiles are included.

The `-L` parameter at outside can be omitted. In real setups the `-R` parameter
on inside setups contains the IP or IP6 address of the outside server, or if
DNS recursion is used, the IP address of the DNS server of your provider.

You can then use `ssh -x -v 1.2.3.5` to get a SSH connection to `192.168.2.222`
and use the SSH proxy options to setup a web browser environment that runs
across the tunnel.

You can also do that with ICMP: `-i` and ICMP on IPv6: `-I` or DNS on UDP via
IPv6: `-U`.
It's also possible to switch tunnel from DNS to ICMP beyond your SSH connection,
as the TCP state is kept in local and remote kernel and not in the bridge.

fraud-bridge will leave stdout open for reporting errors or verbose messages,
so you need to run it on a screen or redirect output to /dev/null if you need
it running in background.

*proudly sponsored by:*
<p align="center">
<a href="https://github.com/c-skills/welcome">
<img src="https://github.com/c-skills/welcome/blob/master/logo.jpg"/>
</a>
</p>

