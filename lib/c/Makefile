LIBS= -lcrypto

CC?= gcc

WARNFLAGS= -Wall
CFLAGS+= $(WARNFLAGS)

passforge: passforge.c
	$(CC) -std=c99 $(CFLAGS) -o passforge passforge.c $(LIBS)

clean:
	rm -f passforge passforge.o
