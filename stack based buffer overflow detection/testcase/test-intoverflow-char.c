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
  char c;
//int c;
   int b,d;
  char input[4];
  int  fd1 = open(argv[1], O_RDONLY | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);

//	int *buf, i;
// 	c=  4294967200u ;
	//c=10;
  read(fd1, input, 4);
 if (input[0] == 'b') {
		
	//b=( int)input[2];
	//printf("the b is %u \n", b);
	//d=b;
	 c=((char)input[2])+'1';
// 		c=(int) input[2]+2147483600;
	
	//c=input[1];
	d= (int)input[1];
	//c=(unsigned int)input [3];
//	printf("the input 2 is %d  \n", (int)input[2]);	
 //	printf("the result is %d  \n", c);
	if (c >'f'){
	printf("OK");
}
	//buf = malloc(a );   
        //if(!buf)
          //      return;
       /* for(i = 0; i < b; i++)
                buf[i] = i;             
        while(i-- > 0)
                printf("%x ", buf[i]);  
        printf("\n");
        free(buf);*/

//c=a/b;
	//printf("the result is %d \n", c);

}
  return 0;
}


	/*printf("input 1 is %d \n", b);

	printf("c is is %u \n", c+b);
        buf = malloc(b +c );   
        if(!buf)
                return;
        for(i = 0; i < b; i++)
                buf[i] = i;             
        while(i-- > 0)
                printf("%x ", buf[i]);  
        printf("\n");
        free(buf);
*/
