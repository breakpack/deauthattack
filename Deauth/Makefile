CC = gcc
CFLAGS = -Wall -lpcap
LIBS = -lpcap

deauth-attack: main.c
	$(CC) $(CFLAGS) -o deauth-attack main.c $(LIBS)

clean:
	rm -f deauth-attack
