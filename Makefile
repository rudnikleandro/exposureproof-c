CC = clang
CFLAGS = -Wall -Wextra -Werror
LDLIBS = -lresolv

TARGET = exposureproof
SRC = main.c

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDLIBS)

clean:
	rm -f $(TARGET)