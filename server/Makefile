CC ?= $(CROSS_COMPILE)gcc
USE_AESD_CHAR_DEVICE ?= 1
CFLAGS ?= -g -Wall -Werror
LDFLAGS ?= -lpthread -lrt
TARGET_AESDSOCKET := aesdsocket
OBJS := $(TARGET_AESDSOCKET).o
.PHONY: default all

all: default

default: $(TARGET_AESDSOCKET)

$(TARGET_AESDSOCKET): $(OBJS)
	$(CC) $(FLAGS) $^ -o $@ $(INCLUDES) $(LDFLAGS)

$(TARGET_AESDSOCKET).o: $(TARGET_AESDSOCKET).c
	$(CC) $(CFLAGS) -DUSE_AESD_CHAR_DEVICE=$(USE_AESD_CHAR_DEVICE) -c $(TARGET_AESDSOCKET).c

clean:
	rm -f $(TARGET_AESDSOCKET) *.o
