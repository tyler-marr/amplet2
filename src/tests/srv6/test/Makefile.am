TESTS=srv6_register.test srv6_process_ipv4.test srv6_report.test srv6_unresolved_target.test
check_PROGRAMS=srv6_register.test srv6_process_ipv4.test srv6_report.test srv6_unresolved_target.test

check_LTLIBRARIES=testsrv6.la
testsrv6_la_SOURCES=../srv6.c
nodist_testsrv6_la_SOURCES=../srv6.pb-c.c
testsrv6_la_CFLAGS=-rdynamic -DUNIT_TEST
testsrv6_la_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lprotobuf-c -levent

srv6_register_test_SOURCES=srv6_register_test.c
srv6_register_test_LDADD=testsrv6.la

srv6_process_ipv4_test_SOURCES=srv6_process_ipv4_test.c
srv6_process_ipv4_test_LDADD=testsrv6.la

srv6_report_test_SOURCES=srv6_report_test.c
srv6_report_test_LDADD=testsrv6.la

srv6_unresolved_target_test_SOURCES=srv6_unresolved_target_test.c
srv6_unresolved_target_test_LDADD=testsrv6.la

AM_CFLAGS=-g -Wall -W -rdynamic -DUNIT_TEST
INCLUDES=-I../ -I../../ -I../../../common/
