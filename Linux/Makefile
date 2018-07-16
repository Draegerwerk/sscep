#
# Makefile for Linux
#

BINDIR = /opt/CertNanny/bin
MANDIR = /usr/local/man/man8

CC	= gcc
#WITH_DEBUG   = -g
OPENSSL = /usr/lib/x86_64-linux-gnu
CFLAGS	= -Wall -O $(WITH_DEBUG) -I /usr/include/openssl

LDFLAGS = -L$(OPENSSL)
LDLIBS = -lcrypto -lssl

MAN	= sscep.8
PROG	= sscep
OBJS    = sscep.o init.o net.o sceputils.o pkcs7.o ias.o fileutils.o configuration.o engine.o

all: $(PROG)_static $(PROG)_dyn

$(PROG)_static: $(OBJS)
	$(CC) $(CFLAGS) -static -o $(PROG)_static $(OBJS) $(OPENSSL)/libcrypto.a $(OPENSSL)/libssl.a -ldl $(LDLIBS) $(LDFLAGS)

$(PROG)_dyn: $(OBJS)
	$(CC) $(CFLAGS) -o $(PROG)_dyn $(OBJS) $(LDLIBS) $(LDFLAGS)

clean:
	rm -vf $(PROG)_dyn $(PROG)_static $(OBJS) $(MAN) core;

install:
	echo "TODO: install target"

package: all
	echo "Creating package..."
	Linux/make_Linux_package.sh

