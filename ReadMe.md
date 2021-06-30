arpobserver
===========

[![Build](https://github.com/cgzones/arpobserver/workflows/Main%20CI/badge.svg)](https://github.com/cgzones/arpobserver/actions?query=workflow%3Amain)
[![GitHub license](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](https://raw.githubusercontent.com/cgzones/arpobserver/master/COPYING)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/cgzones/arpobserver.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cgzones/arpobserver/alerts/)

Arpobserver is a tool similar to [arpwatch](https://ee.lbl.gov/). It main purpose is to monitor the network and
act on discovered Ethernet/IP pairings. Arpobserver has been forked of from
[addrwatch](https://github.com/fln/addrwatch).

Main features of arpobserver:

* IPv4 and IPv6 address monitoring
* Monitoring multiple network interfaces
* Monitoring of VLAN tagged (802.1Q) packets
* Output to stdout, plain text file, syslog, sqlite3 db, MySQL db
* Monitoring of Ethernet/IP pairing changes

A difference between arpwatch and arpobserver is the format of output
files.

Arpwatch stores only current state of the network ethernet/ip pairings and
allows to send email notification when a pairing change occurs. This is fine
for small and rather static networks. In arpwatch case all the history of
pairings is saved only in administrators mailbox. When arpwatch is used for
monitoring dozen or more networks it becomes hard to keep track of the historic
address usage information.

Arpobserver does not keep persistent network pairings state but instead logs all
the events that allow Ethernet/IP pairing discovery. For IPv4 it is ARP
requests, ARP replies and ARP ACD (Address Conflict Detection) packets. For
IPv6 it uses ICMPv6 Neighbor Discovery and (DAD) Duplicate Address Detection
packets (Neighbor Solicitations, Neighbor Advertisements, Router Solicitations,
Router Advertisements).

The output file produced by arpobserver is similar to arpwatch. Example of
arpobserverd output file:

```
1329486484 eth0 0 00:aa:bb:cc:dd:ee fe80::2aa:bbff:fecc:ddee ND_NS
1329486485 eth0 0 00:aa:bb:cc:dd:ee 192.168.1.1 ARP_REQ
1329486485 eth0 0 00:aa:bb:ff:00:11 192.168.1.3 ARP_ACD
1329486486 eth0 7 00:11:11:11:11:11 fe80::211:11ff:fe11:1111 ND_NS
1329486487 eth0 7 00:22:22:22:22:22 fe80::222:22ff:fe22:2222 ND_DAD
1329486488 eth0 7 00:33:33:33:33:33 192.168.2.2 ARP_REQ
```

For each pairing discovery event arpobserver produce time-stamp, interface,
vlan_tag (untagged packets are marked with 0 vlan_tag), Ethernet address, IP
address and packet type separated by spaces.

To prevent arpobserver from producing too many duplicate output data in active
networks rate-imiting should be used. Read more in [Ratelimiting](#Ratelimiting) section.

Modular architecture
--------------------

Arpobserver is written in a modular way. Different output
modules can be configured and started independently from the main data
collection service.

Application architecture:

```
                                                +--------------------+
                                            +-->| arpobserver_stdout |
                                            |   +--------------------+
                                            |
                                            |   +--------------------+
             +--------------+               +-->| arpobserver_syslog |
     network |              | shared memory |   +--------------------+
    ---------> arpobserverd +-------------->|
             |              |               |   +--------------------+
             +--------------+               +-->| arpobserver_mysql  |
                                            |   +--------------------+
                                            |
                                            |   +--------------------+
                                            +-->| arpobserver-checkd |
                                                +--------------------+
```

In the diagram boxes represent separate processes. Main **arpobserverd** process is
responsible for listening on all configured network interfaces and dumping all
data to a shared memory segment. Output modules have be be started separately,
they poll shared memory segment for changes and writes data to a specific output
format. Current version supports **stdout**, **syslog** and **mysql** output
formats.

Installation
------------

To compile arpobserver you must have following development libraries:

* libevent 2.0
* libpcap
* mysqlclient (optional)
* sqlite3 (optional)

To compile arpobserver with option features auto detected:

```
$ ./configure
$ make
$ make install
```

If you do not want to install arpobserver to the system, skip the 'make install'
step. You can find main arpobserverd binary and all output and check arpobserver-\*
binaries in 'src' directory.

Building from repo
------------------

If sources are obtained directly from the git repository (instead of
distribution source package) project has to be bootstrapped using
autoreconf/automake. A helper shell script `autogen.sh` is included in the
repository for that. Note that bootstraping autotools project requires autoconf
and automake to be available on the system.

Example command to bootstrap autotools:

```
./autogen.sh
```

Usage
-----

When started like this arpobserverd opens first non loopback interface and start
logging event to the console without writing anything to disk. All events
are printed to stdout, debug, warning, and err messages are printed to stderr.

If you get the error message `ERR: No suitable interfaces found!` it usually
means you started arpobserverd as normal user and/or do not have sufficient
privileges to start sniffing on network interface.
You should start arpobserverd as root but drop privileges by switching to a non
privileged user:

```
$ sudo arpobserverd --user nobody
```

You can specify which network interface or interfaces should be monitored by
passing interface names as arguments. For example:

```
$ arpobserverd eth0 tap0
```

To find out about more usage options:

```
$ arpobserverd --help
```

More detailed information can be found in the man pages in the 'man' directory.

You can find example systemd service files in the 'systemd' directory.

Ratelimiting
------------

If used without ratelimiting arpobserver reports Etherment/IP pairing every time it
gets usable ARP or IPv6 ND packet. In actively used networks it generates many
duplicate pairings especially for routers and servers.

Ratelimiting option 'RateLimit=NUM' suppress output of duplicate
pairings for at least NUM seconds. In other words if arpobserver have discovered
some pairing (mac,ip) it will not report (mac,ip) again unless NUM seconds have
passed.

There is one exception to this rule to track Ethernet address changes. If
arpobserver have discovered pairings: (mac1,ip),(mac2,ip),(mac1,ip) within
ratelimit time window it will report all three pairings. By doing so
ratelimiting will not lose any information about pairing changes.

For example if we have a stream of events:

| time | MAC address       | IP address
|------|-------------------|------------
| 0001 | 11:22:33:44:55:66 | 192.168.0.1
| 0015 | 11:22:33:44:55:66 | 192.168.0.1
| 0020 | aa:bb:cc:dd:ee:ff | 192.168.0.1
| 0025 | aa:bb:cc:dd:ee:ff | 192.168.0.1
| 0030 | 11:22:33:44:55:66 | 192.168.0.1
| 0035 | 11:22:33:44:55:66 | 192.168.0.1
| 0040 | aa:bb:cc:dd:ee:ff | 192.168.0.1
| 0065 | aa:bb:cc:dd:ee:ff | 192.168.0.1

With RateLimit=100 we would get:

| time | MAC address       | IP address
|------|-------------------|------------
| 0001 | 11:22:33:44:55:66 | 192.168.0.1
| 0020 | aa:bb:cc:dd:ee:ff | 192.168.0.1
| 0030 | 11:22:33:44:55:66 | 192.168.0.1
| 0040 | aa:bb:cc:dd:ee:ff | 192.168.0.1

Without such exception output would be:

| time | MAC address       | IP address
|------|-------------------|------------
| 0001 | 11:22:33:44:55:66 | 192.168.0.1
| 0020 | aa:bb:cc:dd:ee:ff | 192.168.0.1

And we would lose information that address 192.168.0.1 was used by Ethernet
address 11:22:33:44:55:66 between 30-40th seconds.

To sum up ratelimiting reduces amount of duplicate information without losing
any ethernet address change events.

Ratelimit option essentially limits data granularity for IP address usage
duration information (when and for what time period specific IP address was
used). On the other hand without ratelimiting at all you would not get very
precise IP address usage duration information anyways because some hosts might
use IP address without sending ARP or ND packets as often as others
do.


If NUM is set to 0, ratelimiting is disabled and all pairing discovery events
are reported.

If NUM is set to -1, ratelimiting is enabled with infinitely long time window
therefore all duplicate pairings are suppressed indefinitely. In this mode
arpobserver acts almost as arpwatch with the exception that ethernet address
changes are still reported.

It might look tempting to always use arpobserver with RateLimit=-1 however by
doing so you lose the information about when and for what period of time
specific IP address was used. There will be no difference between temporary IPv6
addressed which was used once and statically configured permanent addresses.

Event types
-----------

Ethernet/IP pairing discovery can be triggered by these types of events:

* ARP_REQ - ARP Request packet. Sender hardware address (ARP header) and sender
  protocol address (ARP header) is saved.
* ARP_REP - ARP Reply packet. Sender hardware address (ARP header) and sender
  protocol address (ARP header) is saved.
* ARP_ACD - ARP Address collision detection packet. Sender hardware address
  (ARP header) and target protocol address (ARP header) is saved.
* ND_NS - Neighbor Solicitation packet. Source link-layer address (NS option)
  and source address (IPv6 header) is saved.
* ND_NA - Neighbor Advertisement packet. Target link-layer address (NA option)
  and source address (IPv6 header) is saved.
* ND_DAD - Duplicate Address Detection packet. Source MAC (Ethernet header)
  and target address (NS header) is saved.
* ND_RA - Router Advertisement packet. Source link-layer address (from NS option)
  and source address (from IPv6 header) is saved.
* ND_RS - Router Solicitation packet. Source link-layer address (from NS option)
  and source address (from IPv6 header) is saved.

Unexpected packets
------------------

When an invalid or unknown packet is detected arpobserver will log an according
message and also print the raw packet decoded in base64. This packet dump can
be converted to with your favorite base64 decoder
(e.g. https://cryptii.com/pipes/base64-to-hex) and parsed with packet decoders,
like https://hpd.gasmi.net/ or http://eon.sadjad.org/phd/.
