
/* mlogin: minimalistic login                */
/* Copyright (c) 2019  Ørjan Malde           */
/* Released under LGPL, see COPYRIGHT.MLOGIN */

#include <unistd.h>
#include <pwd.h>

int switch_user_context(struct passwd* pwd, const char* username)
{
	(void)username;

	if(setgid(pwd->pw_gid))
		return 1;
	if(setuid(pwd->pw_uid))
		return 1;
	return 0;
}
