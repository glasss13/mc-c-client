CC=gcc

bin = bin

client: src/main.o src/network.o src/p_string.o src/packet.o src/socket.o src/varint.o src/cJSON.o src/encryption.o src/compression.o
	$(CC) -g -o $(bin)/$@ src/main.o src/network.o src/p_string.o src/packet.o src/socket.o src/varint.o src/cJSON.o src/encryption.o src/compression.o -lssl -lcrypto -lz
	make clean

.PHONY: clean

clean:
	rm -f src/*.o