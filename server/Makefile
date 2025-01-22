CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall -Wextra

default: all

all: aesdsocket

aesdsocket: aesdsocket.o
	$(CC) $(CFLAGS) -o aesdsocket aesdsocket.o

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f aesdsocket *.o

.PHONY: clean
