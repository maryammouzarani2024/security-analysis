#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>	

#define ERROR(x) do { perror(x); exit(-1); } while (0);
#define SIZE_CMD 14
const char cmd[SIZE_CMD] = "/usr/bin/cat ";


void *strcat_(char *dst, const char * src){
	int i=0,j=0;
	while(dst[i]){
	i++;
	}
	while (src[j]){
	dst[i]=src[j];
	i++;
	j++;
	}
	return dst;
}
int main(int argc, char *argv[]) {
	if (argc<2)
		return -1;

	int  fd1 = open(argv[1], O_RDONLY );
	char sys[512];
	char input[12];
	read(fd1, input, 10);

		strcpy(sys, cmd);
		strcat_(sys, input);
		switch(1==1){
			case true:
				system(sys);
			default:
				break;    
}
    return 0;
}

