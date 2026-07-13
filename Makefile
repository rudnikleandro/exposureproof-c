CC = clang
CFLAGS = -Wall -Wextra -Werror

TARGET = exposureproof
SRC = main.c

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)