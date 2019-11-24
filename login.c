/* mlogin: minimalistic login                */
/* Copyright (c) 2019  Ørjan Malde           */
/* Released under LGPL, see COPYRIGHT.MLOGIN */

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
#include "os/os.h"

static bool do_login(struct passwd* pwd, int pflag)
{
	char *	comspec;
	size_t	envlen;
	char **	envp;
	char *	envstrs;
	char *	envptrs[8];
	char	envbuff[3072];

	if(*pwd->pw_shell == '\0')
		pwd->pw_shell = "/bin/sh"; /* if /bin/sh doesn't exist, I do not care. blow up. */

	if(chdir(pwd->pw_dir) < 0) {
		printf("no home directory %s!\n", pwd->pw_dir); /* handle -EPERM, -ENOMEM, -ESYMLNK */

		if(chdir("/") == -1) {
			printf("chdir failed with %s", strerror(errno));
			return false;
		} else {
			pwd->pw_dir = "/";
		}
	}

	if(pflag) {
		envp = environ;

		(void)setenv("HOME", pwd->pw_dir, 1);
		(void)setenv("SHELL", pwd->pw_shell, 1);
		(void)setenv("TERM", "xterm", 0); /* rrrr. needs researching */
		(void)setenv("LOGNAME", pwd->pw_name, 1);
		(void)setenv("USER", pwd->pw_name, 1);
		(void)setenv("PATH", "/local/sbin:/local/bin:/sbin:/bin", 0);
	} else {
		envlen  = snprintf(envbuff,0,"HOME=%s",pwd->pw_dir) + 1;
		envlen += snprintf(envbuff,0,"SHELL=%s",pwd->pw_shell) + 1;
		envlen += snprintf(envbuff,0,"TERM=%s","xterm") + 1;
		envlen += snprintf(envbuff,0,"LOGNAME=%s",pwd->pw_name) + 1;
		envlen += snprintf(envbuff,0,"USER=%s",pwd->pw_name) + 1;
		envlen += snprintf(envbuff,0,"PATH=%s","/local/sbin:/local/bin:/sbin:/bin") + 1;

		if ((comspec = getenv("ComSpec")) || (comspec = getenv("COMSSPEC")))
			envlen += snprintf(envbuff,0,"COMSPEC=%s",comspec) + 1;

		if (envlen <= sizeof(envbuff)) {
			envp    = envptrs;
			envstrs = envbuff;
		} else if ((envstrs = calloc(envlen,1))) {
			envp    = envptrs;
		} else {
			return false;
		}

		envp[0]  = envstrs;
		envstrs += sprintf(envstrs,"HOME=%s",pwd->pw_dir) + 1;

		envp[1]  = envstrs;
		envstrs += sprintf(envstrs,"SHELL=%s",pwd->pw_shell) + 1;

		envp[2]  = envstrs;
		envstrs += sprintf(envstrs,"TERM=%s","xterm") + 1;

		envp[3]  = envstrs;
		envstrs += sprintf(envstrs,"LOGNAME=%s",pwd->pw_name) + 1;

		envp[4]  = envstrs;
		envstrs += sprintf(envstrs,"USER=%s",pwd->pw_name) + 1;

		envp[5]  = envstrs;
		envstrs += sprintf(envstrs,"PATH=%s","/local/sbin:/local/bin:/sbin:/bin") + 1;

		envp[6] = 0;
		envp[7] = 0;

		if (comspec) {
			envp[6]  = envstrs;
			envstrs += sprintf(envstrs,"COMSPEC=%s",comspec) + 1;
		}
	}

	(void)signal(SIGTSTP, SIG_DFL);
	(void)signal(SIGQUIT, SIG_DFL);
	(void)signal(SIGINT, SIG_DFL);

	execve(
		pwd->pw_shell,
		(char *[]){pwd->pw_shell,"-l",0},
		envp);

	return false;
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
	int pflag, iflag = 0;

	while((c = getopt(argc, argv, "pfh:iw")) != -1)
		switch(c) {
			case 'p':
				pflag = 1; break;
			case 'f':
				(void)0; break; /* unused, pointless currently */
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

	if(pwd) {
		if(!iflag) {
			char* pw = getpass("Password: ");
			if(!(*pwd->pw_passwd == '\0' && !strlen(pw))) {
				char* pw_encrypted = crypt(pw, pwd->pw_passwd);
				/* if(timingsafe_memcmp(pw_encrypted, pwd->pw_passwd, strlen(pw_encrypted))) { */
				if(memcmp(pw_encrypted, pwd->pw_passwd, strlen(pw_encrypted)) != 0) {
					puts("Login incorrect.");
					explicit_bzero(pw, strlen(pw));
					exit(1);
				}
				explicit_bzero(pw, strlen(pw));
			}
		}
	}
	else {
		/* asking for password even if the user is not found, no /etc/passwd is found, etc. */
		/* this stops easy probing for accounts */
		char* pw = getpass("Password: ");
		puts("Login incorrect.");
		explicit_bzero(pw, strlen(pw));
		exit(1);
	}

	endpwent();

	/* authenticated, attempt to set user context and spawn user shell */
	if(switch_user_context(pwd, username) == 0) {
		if(!do_login(pwd, pflag)) {
			puts("failed to spawn shell.");
		}
	}
	puts("could not switch to specified user.");
}

void usage(void) {
	puts("login -p (preserve environment)");
	puts("login -f (no secondary authentication, unused)");
	puts("login -h (pass remote server name to login, unused)");
	exit(0);
}
