bin_PROGRAMS = login

login_SOURCES =

if HOST_MIDIPIX
        login_SOURCES += os/midipix.c
endif

if HOST_LINUX
        login_SOURCES += os/linux.c
endif

login_SOURCES += login.c
login_SOURCES += compat/explicit_bzero.c
login_SOURCES += compat/timingsafe_memcmp.c
