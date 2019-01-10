CFLAGS += -std=c99 -I.

login: login.c timingsafe_memcmp.c
	$(CC) $(CFLAGS) -o login login.c timingsafe_memcmp.c $(LDFLAGS) $(LIBS)

.PHONY: clean install

clean:
	rm -f *.o login

install:
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp login $(DESTDIR)$(PREFIX)/bin/login
