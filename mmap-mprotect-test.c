#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#define FILENAME "/tmp/tpe-tests"

void touch_file(const char *filename) {

	int fd;

	fd = creat(filename, (mode_t)0755);

	if (fd == -1) {
		perror("Error opening file for writing");
		exit(EXIT_FAILURE);
	}

	close(fd);

}

int do_mmap(const char *filename) {

	int ret = 0;
	int fd;
	int *map;

	touch_file(filename);

	fd = open(filename, 0, (mode_t)0755);

	if (fd == -1) {
		perror("Error opening file for writing");
		exit(EXIT_FAILURE);
	}

	map = mmap(0, 10, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);

	if (map != MAP_FAILED)
		ret = 1;

	perror("exec via mmap");
	
	close(fd);

	unlink(filename);

	return ret;
}

int do_mprotect(const char *filename) {

	int ret = 0;
	int fd;
	int *map;

	touch_file(filename);

	fd = open(filename, 0, (mode_t)0755);

	if (fd == -1) {
		perror("Error opening file for writing");
		exit(EXIT_FAILURE);
	}

	map = mmap(0, 10, PROT_READ, MAP_PRIVATE, fd, 0);

	if (map == MAP_FAILED) {
		printf("mmap write failed in mprotect test\n");
		exit(EXIT_FAILURE);
	}

	ret = mprotect(map, sizeof(unsigned long), PROT_EXEC);

	if (ret == -1)
		ret = 0;
	else
		ret = 1;

	perror("exec via mprotect");
	
	close(fd);

	unlink(filename);

	return ret;
}

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

	ret = setuid(uid);

	if (ret == -1) {
		perror("Unable to setuid");
		exit(EXIT_FAILURE);
	}

	ret = do_mmap(FILENAME);

	ret += do_mprotect(FILENAME);

	return ret;
}
