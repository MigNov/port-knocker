compile:
	$(CC) -g -o port-knocker port-knocker.c `pkg-config libpcap --libs` `pkg-config libxml-2.0 --cflags` `pkg-config libxml-2.0 --libs`

clean:
	rm -f port-knocker

all: clean compile
