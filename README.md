# Fork of dhcpdump
Parse DHCP packets from a network interface

This fork of `dhcpdump` 1.8 by Edwin Groothuis, edwin@mavetju.org (http://www.mavetju.org) collects in a single place bug-fixes and improvements collected over the last 10+ years.

## Changes since 1.8

* Fix the DHCP flags calculation
* Print option 82 content in a more usable way
* Avoid OOB access for the undefined string values
* Get ethertype in edian agnostic way
* Add/remove headers
* Use `char` for strings and `uint8_t` for binary data
* Let the `Makefile` use environment variables
* Spelling fixes
* Remove the unused `strsep` implementation
* Use a stricter filter for DHCP packets
* Add an option to dump packet content in HEX
* More consistent alignment of output
* Avoid extra new lines in parameter request list (option 55)
* Print client identifier as HEX+ASCII
* Print mac addresses with leading zeroes
* Add support for VLAN tagged traffic
* Add option to read traffic from pcap dump file
* Update option names and semantics from IANA ([Rob Gill](https://github.com/rrobgill))
