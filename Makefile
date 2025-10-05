CC = gcc
CFLAGS = -Iinclude -Wall -Wextra -g
LDFLAGS = -L/usr/local/lib -lcapstone -lkeystone -lstdc++ -lm

SRCDIR = src
INCDIR = include
BUILDDIR = build
TARGET = bin/cunfyooz

SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(patsubst $(SRCDIR)/%.c, $(BUILDDIR)/%.o, $(SOURCES))

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILDDIR) bin
