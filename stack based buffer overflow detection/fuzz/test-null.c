#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
  int  j = 0;
  char input[4];
  int  fd1 = open(argv[1], O_RDONLY | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);

  read(fd1, input, 4);
  if (input[0] == 'b') j++;
  if (input[1] == 'a') j++;
  if (input[2] == 'd') j++;
  //if (input[3] == '!') j++;
  if (j >2) {
	
	char *b;
	b=input[3];
 	printf("the output is %s", b);
	}
  return 0;
}
