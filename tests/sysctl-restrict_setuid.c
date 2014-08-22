#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {

	int ret = 0;
	int uid;

	if (argc != 2) {
		printf("Must run with one argument\n");
		exit(EXIT_FAILURE);
	}

	uid = atoi(argv[1]);

	if (!uid) {
		printf("Need to run this as a non-root user\n");
	}

	printf("Test not implemented yet");

	ret = setuid(uid);

	return -1;
}

