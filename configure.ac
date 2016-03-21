AC_INIT([vhost-user-input], 0)

AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AM_SILENT_RULES([yes])

AC_PROG_CC

PKG_CHECK_MODULES([DEPS], [glib-2.0 libsystemd])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES(Makefile)
AC_OUTPUT
