CFLAGS += -std=c99 -I. -Wall -Werror -Wextra -Wundef
LDFLAGS += -lcrypt

login: login.c timingsafe_memcmp.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

.PHONY: clean install

clean:
	rm -f *.o login

install: login
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp login $(DESTDIR)$(PREFIX)/bin/login
