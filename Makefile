#
# $Id: Makefile,v 1.1 2001/08/24 00:44:16 mavetju Exp $
#

O_FILES = dhcpdump.o

C_FLAGS = -Wall -g

.c.o:
	gcc ${C_FLAGS} -c $< -o $@

all: dhcpdump dhcpdump.1

dhcpdump: ${O_FILES}
	gcc -Wall -o $@ ${O_FILES}

dhcpdump.o: dhcpdump.c dhcp_options.h

dhcpdump.1: dhcpdump.pod
	pod2man --release="April 18, 2001" --date="April 18, 2001" --center="FreeBSD General Commands Manual" --section=1 dhcpdump.pod > dhcpdump.1

depend:
	gcc -E -MM *.c > .depend

clean:
	rm -f ${O_FILES} dhcpdump dhcpdump.1

install:
	install -c -o root -g wheel -m 755 dhcpdump /usr/local/bin
	install -c -o root -g wheel -m 644 dhcpdump.1 /usr/local/man/man1

uninstall:
	rm /usr/local/bin/dhcpdump
	rm /usr/local/man/man1/dhcpdump.1
