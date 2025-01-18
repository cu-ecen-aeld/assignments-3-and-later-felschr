CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall -Wextra

writer: writer.o
	$(CC) $(CFLAGS) -o writer writer.o

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f writer *.o

.PHONY: clean
