TESTS = check_base64 check_dllist

check_PROGRAMS = ${TESTS}


check_base64_SOURCES = check_base64.c $(top_builddir)/src/base64.h
check_base64_LDADD = @CHECK_LIBS@ $(top_builddir)/src/base64.o

check_dllist_SOURCES = check_dllist.c $(top_builddir)/src/dllist.h
check_dllist_LDADD = @CHECK_LIBS@ $(top_builddir)/src/dllist.o
