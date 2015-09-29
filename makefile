CC=gcc
CFLAGS=-w
LDIR =/usr/lib
LIBS=-lgcrypt
ODIRDEC=Decryptor
ODIRENC=Encryptor
all: directories gatorenc gatordec

directories:
	mkdir $(ODIRDEC) $(ODIRENC)
gatorenc:
	$(CC) -o $(ODIRENC)/gatorenc gatorenc.c $(LIBS)
gatordec:
	$(CC) -o $(ODIRDEC)/gatordec gatordec.c $(LIBS)
.PHONY: clean
clean:
	rm -rf $(ODIRDEC) $(ODIRENC)
