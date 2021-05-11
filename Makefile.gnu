LOCALBASE?= /usr/local/

PROG=	filter-admdscrub
MAN=	filter-admdscrub.8
BINDIR=	${LOCALBASE}/libexec/opensmtpd/
MANDIR=	${LOCALBASE}/share/man/man8

BINOWN?=	root
BINGRP?=	root
BINPERM?=	755

SRCS+=	main.c mheader.c

CFLAGS+=-I${LOCALBASE}/include
CFLAGS+=-Wall -I${.CURDIR}
CFLAGS+=-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations
CFLAGS+=-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare
CFLAGS+=-I${CURDIR} -I${CURDIR}/openbsd-compat/

LDFLAGS+=-L${LOCALBASE}/lib
LDLIBS+=-levent -lopensmtpd

INSTALL?=	install

NEED_STRLCAT?=		1
NEED_PLEDGE?=		1

.PHONY: all
all: ${PROG}

ifeq (${NEED_STRLCAT}, 1)
SRCS+=		${CURDIR}/openbsd-compat/strlcat.c
CFLAGS+=	-DNEED_STRLCAT=1

strlcat.o: ${CURDIR}/openbsd-compat/strlcat.c
	${CC} ${CFLAGS} -c -o strlcat.o ${CURDIR}/openbsd-compat/strlcat.c
endif
ifeq (${NEED_PLEDGE}, 1)
CFLAGS+=	-DNEED_PLEDGE=1
endif

${SRCS:.c=.d}:%.d:%.c
	 ${CC} ${CFLAGS} -MM $< >$@

OBJS=		${notdir ${SRCS:.c=.o}}

${PROG}: ${OBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LDLIBS}

.PHONY: clean
clean:
	rm -f *.d *.o ${PROG}

.PHONY: install
install: ${PROG}
	${INSTALL} -o ${BINOWN} -g ${BINGRP} -m ${BINPERM} ${PROG} ${BINDIR}
