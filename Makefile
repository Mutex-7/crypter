# Compiler rules:
CC = gcc
CFLAGS = -Wall -g
OBJDIR = objects

# Set up objects directory if it doesn't already exist
directory:
	mkdir -p $(OBJDIR)

# Build object files:
$(OBJDIR)/hello-world.o: directory hello-world.c
	$(CC) $(CFLAGS) -c hello-world.c -o $(OBJDIR)/hello-world.o

$(OBJDIR)/crypter.o: directory crypter.c
	$(CC) $(CFLAGS) -c crypter.c -o $(OBJDIR)/crypter.o

$(OBJDIR)/fib.o: directory fib.c
	$(CC) $(CFLAGS) -c fib.c -o $(OBJDIR)/fib.o

# Build executables
hello-world: $(OBJDIR)/hello-world.o
	$(CC) $(CFLAGS) $(OBJDIR)/hello-world.o -o hello-world

crypter: $(OBJDIR)/crypter.o
	$(CC) $(CFLAGS) $(OBJDIR)/crypter.o -o crypter

fib: $(OBJDIR)/fib.o
	$(CC) $(CFLAGS) $(OBJDIR)/fib.o -o fib

all: directory hello-world crypter fib

clean:
	rm -f $(OBJDIR)/*
	rm hello-world
	rm crypter
	rm fib
