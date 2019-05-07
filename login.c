/* mlogin: minimalistic login                */
/* Copyright (c) 2019  Ørjan Malde           */
/* Released under LGPL, see COPYRIGHT.MLOGIN */

#define _GNU_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <grp.h>
#include <pwd.h>
#include <errno.h>
#include <signal.h>
#ifdef __midipix__
#define IFLAG 1
#else
#define IFLAG 0
#endif

#include "login.h"

#ifndef HAVE_EXPLICIT_BZERO
void explicit_bzero(void*, size_t);
#endif


static bool switch_user_context(struct passwd* pw, const char* username)
{
	/* temporary */
	#ifndef INSECURE
	if(initgroups(username, pw->pw_gid) == -1) {
		printf("initgroups failed: %s", strerror(errno));
		exit(1);
	}
	#endif
	
	#ifdef INSECURE
		if((setuid(pw->pw_uid) != -1) && (setgid(pw->pw_gid) != -1))
			return true;
		return false;
	#else
	gid_t oldgid = getegid();
	uid_t olduid = geteuid();
	
	if((setegid(pw->pw_gid) != -1) && (setgid(pw->pw_gid) != -1) && (seteuid(pw->pw_uid) != -1) && (setuid(pw->pw_uid) != -1)) {
		gid_t newgid = getgid();
		uid_t newuid = getuid();
		#ifdef debug
		printf("old gid %d\n", oldgid);
		printf("old uid %d\n", olduid);
		printf("new gid %d\n", newgid);
		printf("new uid %d\n", newuid);
		#endif
		if((newgid == oldgid) && (newuid == olduid))
			return true;
	}
	return false;
	#endif
}

int main(int argc, char **argv)
{
	/* we don't want ^D etc to mess up the logic */
	(void)signal(SIGTSTP, SIG_IGN);
	(void)signal(SIGQUIT, SIG_IGN);
	(void)signal(SIGINT, SIG_IGN);

	struct passwd *pwd;
	char* username = NULL;
	int c;
	int pflag, fflag, iflag, wflag = 0;

	while((c = getopt(argc, argv, "pfh:iw")) != -1)
		switch(c) {
			case 'p':
				pflag = 1; break;
			case 'f':
				fflag = 1; break; /* unused, pointless currently */
			case 'h':
				if(getuid()) {
					exit(1);
				}
				break;
			case 'i':
				iflag = IFLAG; break;
			default:
			case '?':
				usage();
				break;
		}
	argv += optind;

	if(*argv)
		username = *argv;
	else {
		printf("login: ");
		fflush(0);
		(void)scanf("%ms", &username);
	}
	pwd = getpwnam(username);

	if(!iflag)
	{
		char* pw = getpass("Password: ");
		if(pwd) {
			/* if hash == 0 then authenticated = true */
			if(!(*pwd->pw_passwd == '\0' && !strlen(pw))) {
				char* pw_encrypted = crypt(pw, pwd->pw_passwd);
				if(!timingsafe_memcmp(pw_encrypted, pwd->pw_passwd, strlen(pw_encrypted))) {
					puts("Login incorrect.");
					explicit_bzero(pw, strlen(pw));
					free(pw);
					exit(1);
				}
			}
			explicit_bzero(pw, strlen(pw));
		} else {
			/* user doesn't exist, bail */
			puts("Login incorrect.");
			explicit_bzero(pw, strlen(pw));
			free(pw);
			exit(1);
		}
	}
	
	endpwent();

	/* authenticated, attempt to set user context and spawn user shell */
	if(switch_user_context(pwd, username)) {
		if(*pwd->pw_shell == '\0')
			pwd->pw_shell = "/bin/sh"; /* if /bin/sh doesn't exist, I do not care. blow up. */

		if(chdir(pwd->pw_dir) < 0) {
			printf("no home directory %s!\n", pwd->pw_dir); // handle -EPERM, -ENOMEM, -ESYMLNK
				if(chdir("/") == -1) {
					printf("chdir failed with %s", strerror(errno));
					exit(1); /* no-one can save you now */
				}
			pwd->pw_dir = "/";
		}

		if(!pflag)
			(void)clearenv();

		(void)setenv("HOME", pwd->pw_dir, 1);
		(void)setenv("SHELL", pwd->pw_shell, 1);
		(void)setenv("TERM", "xterm", 0); /* rrrr. needs researching */
		(void)setenv("LOGNAME", pwd->pw_name, 1);
		(void)setenv("USER", pwd->pw_name, 1);
#if 0
		(void)setenv("PS1", "$ ", 0);
#endif
		(void)setenv("PATH", "/local/sbin:/local/bin:/sbin:/bin", 0);

		(void)signal(SIGTSTP, SIG_DFL);
		(void)signal(SIGQUIT, SIG_DFL);
	        (void)signal(SIGINT, SIG_DFL);

		execlp(pwd->pw_shell, "-i", (const char*)NULL);
		printf("login failed with error: %s", strerror(errno));
		exit(1);
	}
	puts("could not switch to specified user.");
}

void usage(void) {
	puts("login -p (preserve environment)");
	puts("login -f (no secondary authentication, unused)");
	puts("login -h (pass remote server name to login, unused)");
	exit(0);
}
