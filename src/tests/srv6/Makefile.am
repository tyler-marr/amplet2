EXTRA_DIST=*.h srv6.proto
SUBDIRS= . test
BUILT_SOURCES=srv6.pb-c.c
CLEANFILES=srv6.pb-c.c srv6.pb-c.h

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-srv6
amp_srv6_SOURCES=../testmain.c
amp_srv6_LDADD=srv6.la -L../../common/ -lamp -lprotobuf-c -lunbound -levent
amp_srv6_LDFLAGS=-Wl,--no-as-needed

test_LTLIBRARIES=srv6.la
srv6_la_SOURCES=srv6.c
nodist_srv6_la_SOURCES=srv6.pb-c.c
srv6_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c -levent

INCLUDES=-I../ -I../../common/

install-exec-hook:
	setcap 'CAP_NET_RAW=ep' $(DESTDIR)/$(bindir)/amp-srv6

srv6.pb-c.c: srv6.proto
	protoc-c --c_out=. srv6.proto
	protoc --python_out=../python/ampsave/tests/ srv6.proto
