bin_PROGRAMS = dhcpdump
dhcpdump_SOURCES = dhcpdump.c dhcp_options.h
man_MANS = dhcpdump.1

dhcpdump.1: dhcpdump.pod
	$(PERL2MAN_RULE)
PERL2MAN_RULE = \
	pod2man --release="November 21, 2003" --date="November 21, 2003" --center="General Commands Manual" --section=1 $? > $@
