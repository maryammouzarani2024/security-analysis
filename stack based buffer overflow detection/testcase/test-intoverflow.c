#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
int main(int argc, char** argv)
{
  int  j = 0;
	   int a=10,b=15,c,d;
  char input[4];
  int  fd1 = open(argv[1], O_RDONLY | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);

	int *buf, i;
 	c=  4294967250u ;
	read(fd1, input, 4);		
	b=(  int)input[1];
	//d=b+c;
	  char e;
	e= input[2];
	//printf("the result is %u %d \n", d, sizeof(c));
	if (b>e){
	//d=a/((int)input[0]);		
	//if (d>0){
		printf("Hi");		
	//}
}
  return 0;
}

