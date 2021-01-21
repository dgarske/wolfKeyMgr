# cert service
# Copyright (C) 2013 wolfSSL Inc.
# All rights reserved.
#

AC_PREREQ(2.59)

AC_INIT([cert],[0.8],[http://www.wolfssl.com])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_HEADER(src/config.h)
AC_CONFIG_MACRO_DIR(m4)
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE(subdir-objects foreign)

# Install path
#AC_PREFIX_DEFAULT(/usr/local/wolfssl)
AC_ARG_PROGRAM
AC_DEFUN([PROTECT_AC_USE_SYSTEM_EXTENSIONS],
         [AX_SAVE_FLAGS
          AC_LANG_PUSH([C])
          AC_USE_SYSTEM_EXTENSIONS
          AC_LANG_POP([C])
          AX_RESTORE_FLAGS
          ])
#PROTECT_AC_USE_SYSTEM_EXTENSIONS

AX_TLS([AM_CFLAGS="$AM_CFLAGS -DHAVE_THREAD_LS"],
        AC_MSG_ERROR([Need compiler support for thread local storage. If on OS X try using CC=clang]))

# Make sure configure doesn't add to CFLAGS
CFLAGS="$CFLAGS $C_EXTRA_FLAGS"

# silent
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CC_C_O
AC_PROG_INSTALL

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_SIZEOF(long long, 8)
AC_CHECK_SIZEOF(long, 4)

# Check headers/libs
AC_CHECK_FUNCS([gethostbyname])
AC_CHECK_FUNCS([getaddrinfo])
AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([inet_ntoa])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([socket])
AC_CHECK_LIB(network,socket)

# Requirements
PANDORA_REQUIRE_PTHREAD
PANDORA_REQUIRE_LIBEVENT
WOLF_REQUIRE_LIBWOLFSSL


# compiler options
CFLAGS="$CFLAGS -Wall -g -O2"

# Checks for typedefs, structures, and compiler characteristics.
if test "$ac_cv_sizeof_long" = "8"; then
    CFLAGS="$CFLAGS -DSIZEOF_LONG=8"
else
    if test "$ac_cv_sizeof_long_long" = "8"; then
        CFLAGS="$CFLAGS -DSIZEOF_LONG_LONG=8"
    fi
fi


# pthread flags
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
LIBS="$LIBS $PTHREAD_LIBS"


# system depedent stuff
case "$host_os" in
  *darwin*)
LDFLAGS="$LDFLAGS"
  ;;
esac

# Checks for library functions.
LIB_SOCKET_NSL

# FINAL
AC_CONFIG_FILES([Makefile])

AX_AM_JOBSERVER([yes])

AC_OUTPUT()


# force make clean
echo "---"
echo "Running make clean..."
make clean >/dev/null 2>&1
echo


# output config summary
echo "---"
echo "Configuration summary for $PACKAGE_NAME version $VERSION"
echo ""
echo "   * Installation prefix:       $prefix"
echo "   * System type:               $host_vendor-$host_os"
echo "   * Host CPU:                  $host_cpu"
echo "   * C Compiler:                $CC_VERSION"
echo "   * C Flags:                   $CFLAGS"
echo "   * CPP Flags:                 $CPPFLAGS"
echo "   * LIB Flags:                 $LIB"
