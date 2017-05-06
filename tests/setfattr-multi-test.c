#include <stdlib.h>
#include <fcntl.h>

void tpe_file_read(const char *filename) {
	int fd;

	fd = open(filename, O_RDONLY);

	if (fd == -1) {
		perror("Error opening file for writing");
		exit(EXIT_FAILURE);
	}

	close(fd);
}

int main(int argc, char *argv[]) {

	tpe_file_read("/proc/modules");
	tpe_file_read("/proc/kallsyms");

	return 0;
}

