AC_INIT([mlogin], [0.1])

AC_CONFIG_SRCDIR([login.c])

AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AC_PROG_CC
AC_PROG_CC_C_O

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_CANONICAL_HOST


case $host_os in
	*midipix*)
		HOST_OS=midipix
		;;
	linux*)
		HOST_OS=linux
		;;
	*)
		AC_MSG_ERROR(["$host_os is not supported."])
		;;
esac


AM_CONDITIONAL([HOST_MIDIPIX], [test x$HOST_OS = xmidipix])
AM_CONDITIONAL([HOST_LINUX], [test x$HOST_OS = xlinux])


AC_OUTPUT
