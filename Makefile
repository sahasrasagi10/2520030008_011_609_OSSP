CC = gcc
CFLAGS = -Wall -Wextra

TARGET = osmanager

SOURCES = main.c osmanager.c

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET)

clean:
	rm -f $(TARGET)