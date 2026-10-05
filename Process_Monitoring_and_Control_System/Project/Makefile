CC=gcc
CFLAGS=-Wall -Wextra -O2 -pthread
TARGET=osmanager
SOURCES=main.c osmanager.c

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET)

clean:
	rm -f $(TARGET) *.o

.PHONY: clean
