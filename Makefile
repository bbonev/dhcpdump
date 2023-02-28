CFLAGS+=${CPPFLAGS} -Wall -g
LDFLAGS+=-g
LIBS+=-lpcap

all: dhcpdump dhcpdump.8

clean:
	-rm -f dhcpdump.o dhcpdump dhcpdump.8

re:
	${MAKE} clean
	${MAKE} -j all

dhcpdump.8: dhcpdump.pod Makefile
	pod2man --section 8 \
		--date "23 June 2008" \
		--name "DHCPDUMP" \
		--center "User Contributed Software" \
		dhcpdump.pod dhcpdump.8

dhcpdump: dhcpdump.o
	${CC} ${LDFLAGS} -o $@ dhcpdump.o ${LIBS}

dhcpdump.o: dhcpdump.c dhcp_options.h Makefile
	${CC} ${CFLAGS} -c -o $@ dhcpdump.c
