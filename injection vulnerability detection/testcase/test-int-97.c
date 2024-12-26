#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

void
test(unsigned int n)
{
        int *buf, i;
 
        buf = malloc(n * sizeof *buf);    /* BAD */
        if(!buf)
                return;
        for(i = 0; i < n; i++)
                buf[i] = i;               /* BAD */
        while(i-- > 0)
              printf("%x ", buf[i]);    /* BAD */
        printf("\n");
        free(buf);
}
int main(int argc, char** argv)
{
  int  j = 0;
   //char c;
int c;
   int b,d;
  char input[4];
  int  fd1 = open(argv[1], O_RDONLY | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
       int n;
 
        if(argc != 2)
                return 1;
  read(fd1, input, 4);
	n=(int)input[0];
         //    printf("the input is %d \n", n);  
        int *buf, i;
 
        //
	n=200000000*(int)input[2];
        //     printf("the buffer is %d \n ", n+200000000);  
buf = malloc(n);    /* BAD */
        if(!buf)
                return;
        for(i = 0; i < n; i++)
                buf[i] = i;               /* BAD */
        while(i-- > 0)
              printf("%x ", buf[i]);    /* BAD */
        printf("\n");
        free(buf);
        return 0;
}
