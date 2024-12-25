#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <unistd.h>

#include <string.h>
#define ERROR(x)     do { perror(x); exit(-1); } while (0)
#define ASSERT(x, y) do { if (!(x)) { perror(y); exit(-1); } } while (0)

int mytest3(char *a){
//if (a[1]=='a'){
 //int c;
//c=2;
int destLen;
destLen=0;
char dst[20];
char dst2[110];
char dst3[100];
//destLen = strlen(a);
//if (a[2]=='b'){
int i;
printf("hello");
printf("hello \n\n");
        /* POTENTIAL FLAW: using length of the dest where data
         * could be smaller than dest causing buffer overread */
      /* for (i = 0; i < destLen; i++)
        {
            dst[i] = a[i];
        }*/
        //dst[20-1] = '\0';
       // printf("%s", dst);
	strcpy(dst,a);
	printf("hello");
	if (a[2]=='b'){
	   //if (a[3]=='x')
	
}				
	   strcpy(dst2,a);
	  // strcat(dst,dst2);

	if (dst2[1]=='a')
		printf("ok");
	//printf("%d",c);
	if (dst[1]=='a')
		printf("ok");

//}
//}

}

int mytest2(char * a){
	mytest3(a);
}
int mytest(char * a){
	mytest2(a);
}
int main(int argc, char *argv[]) {
    int fd;
    char buffer[10000];
    if (argc != 2) {
        printf("Usage: %s <file>\n", argv[0]);
        exit(-1);
    }

    fd = open(argv[1], O_RDONLY);
    ASSERT(fd != -1, "open");

    /*if (read(fd, &buffer[i], 4) != 4) {
        ERROR("read");
    }*/
    
    /*for (i = 0; i < 4; i++) {
        if (read(fd, &buffer[i], sizeof(char)) != sizeof(char)) {
            ERROR("read");
        }
    }*/

   /*for (i = 4; i >= 0; i--) {
        k = lseek(fd, i, SEEK_SET);
        ASSERT(k != -1, "lseek");
        
        k = read(fd, &buffer[i], sizeof(char));
        ASSERT(k == sizeof(char), "read");
    }
*/

	int size = read(fd, buffer , 10000);
	//printf("the buffer is: %s with size: %d\n",buffer , size);
	mytest(buffer);


    return 0;
}
