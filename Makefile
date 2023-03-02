CFLAGS+=${CPPFLAGS}
CFLAGS+=-Wall -Wextra -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2 -g -O3
LDFLAGS+=-g -Wl,-z,relro -Wl,-z,now
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

VER:=$(shell grep 'define VERSION' version.h|tr -d '\"'|awk '{print $$3}')
mkotar:
	${MAKE} clean
	-dh_clean
	tar \
		--xform 's,^[.],dhcpdump-${VER},' \
		--exclude ./.git \
		--exclude ./.gitignore \
		--exclude ./debian \
		-Jcvf ../dhcpdump_${VER}.orig.tar.xz .
	-rm -f ../dhcpdump_${VER}.orig.tar.xz.asc
	gpg -a --detach-sign ../dhcpdump_${VER}.orig.tar.xz
	cp -fa ../dhcpdump_${VER}.orig.tar.xz ../dhcpdump-${VER}.tar.xz
	cp -fa ../dhcpdump_${VER}.orig.tar.xz.asc ../dhcpdump-${VER}.tar.xz.asc
