
/* mlogin: minimalistic login                */
/* Copyright (c) 2019  Ørjan Malde           */
/* Released under LGPL, see COPYRIGHT.MLOGIN */



int switch_user_context(struct passwd* pwd, const char* username)
{
	if(!getuid()) {
		if(initgroups(username, pwd->pw_gid) == -1) {
			printf("initgroups failed: %s", strerror(errno));
			exit(1);
		}
	}

        /* is this safe? not sure. */
	if(setgid(pwd->pw_gid))
		return false;
	if(setuid(pwd->pw_uid))
		return 1;
	return 0;
}
