#
# $Id$
#

O_FILES = dhcpdump.o

C_FLAGS = -Wall -g

.c.o:
	gcc ${C_FLAGS} -c $< -o $@

all: dhcpdump

dhcpdump: ${O_FILES}
	gcc -Wall -o $@ ${O_FILES}

dhcpdump.o: dhcpdump.c dhcp_options.h

depend:
	gcc -E -MM *.c > .depend

clean:
	rm -f ${O_FILES} dhcpdump

install:
	install -c -o root -g wheel -m 755 dhcpdump /usr/local/bin
	install -c -o root -g wheel -m 644 dhcpdump.1 /usr/local/man/man1

uninstall:
	rm /usr/local/bin/dhcpdump
	rm /usr/local/man/man1/dhcpdump.1
