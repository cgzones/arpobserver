AC_PREREQ([2.69])
AC_INIT([arpobserver],[0.1],[cgzones@googlemail.com])
AM_INIT_AUTOMAKE([-Wall check-news foreign std-options -Werror])
AC_CONFIG_SRCDIR([src/arpobserverd.c])
AC_CONFIG_HEADERS([src/config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for required libraries.
AC_CHECK_LIB([pcap], [pcap_open_live], [], [AC_MSG_ERROR([pcap library is required!])])
AC_CHECK_LIB([rt], [shm_open], [], [AC_MSG_ERROR([shm framework is required!])])

AC_ARG_WITH([check],
    [AS_HELP_STRING([--with-check],
        [Build with testsuite depending on Check (yes,no,check) @<:@default=check@:>@])],
    [with_check=${withval}],
    [with_check=check])
AS_CASE(["$with_check"],
    [yes], [PKG_CHECK_MODULES([CHECK], [check >= 0.11.0], [], [AC_MSG_ERROR([Check not found])])],
    [no], [],
    [PKG_CHECK_MODULES([CHECK], [check >= 0.11.0], [with_check=yes], [with_check=no])])
AM_CONDITIONAL([WITH_CHECK], [test "x$with_check" = "xyes"])

PKG_CHECK_MODULES(LIBEVENT, [libevent >= 1.4], , [
    AC_CHECK_LIB([event], [event_dispatch], , [
        AC_MSG_ERROR([libevent-1.4 or libevent-2.0 required!])
    ])
])

PKG_CHECK_MODULES(LIBEVENT2, [libevent >= 2.0], [
    AC_DEFINE([HAVE_LIBEVENT2], 1, [Define to 1 if you have libevent2])
], [ ])


WITH_SQLITE3="no"
AC_ARG_WITH([sqlite3],
    [AS_HELP_STRING([--with-sqlite3],
        [sqlite3 database output (yes,no,check) @<:@default=check@:>@])],
    [],
    [with_sqlite3=check])
AS_CASE(["$with_sqlite3"],
    [yes], [AC_CHECK_LIB([sqlite3], [sqlite3_open], [], [AC_MSG_ERROR([sqlite3 library not found!])])],
    [no], [],
    [AC_CHECK_LIB([sqlite3], [sqlite3_open])])
AS_IF([test "$ac_cv_lib_sqlite3_sqlite3_open" = yes], [WITH_SQLITE3="yes"])

WITH_MYSQL="no"
AC_ARG_WITH([mysql],
    [AS_HELP_STRING([--with-mysql],
        [mysql database output (yes,no,check) @<:@default=check@:>@])],
    [],
    [with_mysql=check])
AS_CASE(["$with_mysql"],
    [yes], [AC_CHECK_LIB([mysqlclient], [mysql_real_connect], [], [AC_MSG_ERROR([mysql library not found!])])],
    [no], [],
    [AC_CHECK_LIB([mysqlclient], [mysql_real_connect])])
AS_IF([test "$ac_cv_lib_mysqlclient_mysql_real_connect" = yes], [WITH_MYSQL="yes"])
AM_CONDITIONAL([MYSQL], [test x$WITH_MYSQL = xyes])


# Checks for required header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdint.h stdlib.h syslog.h unistd.h], [], [AC_MSG_ERROR([required header file not found!])])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_UINT32_T
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK


# Warning flags
AM_CFLAGS="\
 -Wall\
 -Wcast-qual\
 -Wconversion\
 -Wdeclaration-after-statement\
 -Wextra\
 -Wmissing-format-attribute\
 -Wmissing-noreturn\
 -Wmissing-prototypes\
 -Wno-unused-parameter\
 -Wpointer-arith\
 -Wshadow\
 -Wstrict-prototypes\
 -Wundef\
 -Wunused\
 -Wwrite-strings"

AC_ARG_ENABLE([werror],
    [AS_HELP_STRING([--enable-werror],
        [Treat warnings as errors (default: warnings are not errors)])],
        [enable_werror="$enableval"],
        [enable_werror=no])
AS_IF([test "x$enable_werror" = "xyes"], [AM_CFLAGS="$AM_CFLAGS -Werror"])
AC_SUBST([AM_CFLAGS])


AC_ARG_ENABLE([man],
    [AS_HELP_STRING([--disable-man],
        [Disable man page generation (default: generate man pages with asciidoctor)])],
        [enable_man="$enableval"],
        [enable_man=yes])
AM_CONDITIONAL([ENABLE_MAN], [test "x$enable_man" = "xyes"])


AC_CONFIG_FILES([Makefile
                 conf/Makefile
                 man/Makefile
                 src/Makefile
                 tests/Makefile])
AC_OUTPUT

AC_MSG_RESULT([
  ${PACKAGE_NAME} ${VERSION}

  check:         ${with_check}
  man pages:     ${enable_man}
  sqlite3:       ${WITH_SQLITE3}
  mysql:         ${WITH_MYSQL}
])
