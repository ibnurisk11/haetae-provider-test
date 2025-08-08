CC = gcc
CFLAGS = -fPIC -Wall -Wextra -Iinclude -Ithird_party/haetae \
         -I/usr/include/openssl -I/usr/local/include/openssl \
         -Wno-missing-field-initializers
LDFLAGS = -shared -lssl -lcrypto  # Link dengan OpenSSL

SRC = src/haetae_provider.c src/haetae_keymgmt.c src/haetae_signature.c \
      src/haetae_encoder.c third_party/haetae/reference.c
OBJ = $(SRC:.c=.o)

TARGET = haetae.so  # Output berupa shared library

all: $(TARGET)  # Target utama

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f $(OBJ) $(TARGET)  # Bersihkan file hasil kompilasi