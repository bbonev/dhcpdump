bin_PROGRAMS = dhcpdump
dhcpdump_SOURCES = dhcpdump.c dhcp_options.h
man_MANS = dhcpdump.1

dhcpdump.1: dhcpdump.pod
	$(PERL2MAN_RULE)
PERL2MAN_RULE = \
	pod2man --release="November 03, 2004" --date="November 03, 2004" --center="General Commands Manual" --section=1 $? > $@
