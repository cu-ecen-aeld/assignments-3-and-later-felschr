CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -Wall -Wextra
LDFLAGS ?= -lpthread -lrt
USE_AESD_CHAR_DEVICE ?= y

ifeq ($(USE_AESD_CHAR_DEVICE),y)
	EXTRA_CFLAGS += -DUSE_AESD_CHAR_DEVICE
endif

default: all

all: aesdsocket

aesdsocket: aesdsocket.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(INCLUDES) aesdsocket.o -o aesdsocket $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f aesdsocket *.o *.elf *.map

.PHONY: clean
