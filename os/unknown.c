
/* mlogin: minimalistic login                */
/* Copyright (c) 2019  Ørjan Malde           */
/* Released under LGPL, see COPYRIGHT.MLOGIN */

#include <unistd.h>
#include <pwd.h>

int switch_user_context(struct passwd* pwd, const char* username)
{
	#warning port me!

	(void)username;
	(void)pwd;

	return 0;
}
