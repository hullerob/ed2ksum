
.PHONY: all clean

all: ed2ksum

ed2ksum: ed2ksum.c
	c99 -lcrypto -O3 -s -o ed2ksum ed2ksum.c

clean:
	rm -f ed2ksum
