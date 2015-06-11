
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>


int main(int argc, char *argv[]) {

	int ret = setuid(0);

	if (0 == ret)
		return 0;
	else
		return 1;

}

