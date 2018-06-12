#include <stdio.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int rfib(int n)
{
	if(n <= 1)
	{
		return 1;
	}
	printf("[R] N is %d\n", n);

	return (rfib(n-1) + rfib(n-2));
}

int main(int argc, char* argv[])
{
	if(argc < 2)
	{
		printf("[X] Usage: fib <integer>");
	}

	int n = atoi(argv[1]);
	printf("[M] N is %d\n", n);
	printf("[M] Fibbers gonna fib.\n");
	printf("[M] Fib of %d is: %d\n", n, rfib(n));

	return 0;
}
