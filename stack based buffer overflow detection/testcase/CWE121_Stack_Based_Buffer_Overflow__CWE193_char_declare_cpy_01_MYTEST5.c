/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_01.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE193.label.xml
Template File: sources-sink-01.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Point data to a buffer that does not have space for a NULL terminator
 * GoodSource: Point data to a buffer that includes space for a NULL terminator
 * Sink: cpy
 *    BadSink : Copy string to data using strcpy()
 * Flow Variant: 01 Baseline
 *
 * */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include "std_testcase.h"

#include <wchar.h>
#define ERROR(x)     do { perror(x); exit(-1); } while (0)
#define ASSERT(x, y) do { if (!(x)) { perror(y); exit(-1); } } while (0)


#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

/* MAINTENANCE NOTE: The length of this string should equal the 10 */
#define SRC_STRING "AAAAAAAAAA"

#ifndef OMITBAD

static void bad(char * source)
{
	
    //char *data;
    char data[100];
    //char data2[20];		
    
int j,i;
j=0;
i=0;
while (j< 10)
{
	 data[j]=source[i];
j=j+1;
i=i+1;
}
i=20;
j=10;

if (data[5]=='Q' && data[4]=='A'){
for (i=20;i< strlen(source);i++ )
{
		 data[j]=source[i];
j=j+1;
}
}
    /* FLAW: Set a pointer to a buffer that does not leave room for a NULL terminator when performing
     * string copies in the sinks  */
//    data = dataBadBuffer;
  //  data[0] = '\0'; /* null terminate */
	
        /* POTENTIAL FLAW: data may not have enough space to hold source */

	if (data[1]=='a')
	{        
	printf("OK \n\n	");
	}


}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * data;
    char dataBadBuffer[10];
    char dataGoodBuffer[10+1];
    /* FIX: Set a pointer to a buffer that leaves room for a NULL terminator when performing
     * string copies in the sinks  */
    data = dataGoodBuffer;
    data[0] = '\0'; /* null terminate */
   
{
        char source[10+1] = SRC_STRING;
        /* POTENTIAL FLAW: data may not have enough space to hold source */
        strcpy(data, source);
        printf("%s",data);
    }
}

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_01_good()
{
//    goodG2B();

    char * data;
    char dataBadBuffer[10];
    char dataGoodBuffer[10+1];
    /* FIX: Set a pointer to a buffer that leaves room for a NULL terminator when performing
     * string copies in the sinks  */
    data = dataGoodBuffer;
    data[0] = '\0'; /* null terminate */
    {
        char source[10+1] = SRC_STRING;
        /* POTENTIAL FLAW: data may not have enough space to hold source */
        strncpy(data, source,10);
        printf("%s",data);
    }
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */


int main(int argc, char *argv[]) {
    int fd;
    char buffer[10000];
    if (argc != 2) {
        printf("Usage: %s <file>\n", argv[0]);
        exit(-1);
    } 

    fd = open(argv[1], O_RDONLY);
    ASSERT(fd != -1, "open");
    int size = read(fd, buffer , 10000);

/*
for (i=0;i<1000;i++)
{
	//if (buffer[i]){
	if (i<5)	
		buffer1[i]=buffer[i];
	else
		buffer2[i]=buffer[i];
//}
} */   /* seed randomness */
    //srand( (unsigned)time(NULL) );
	
#ifndef OMITBAD
    printf("Calling bad()...");
    bad(buffer);
    printf("Finished bad()...");
#endif /* OMITBAD */

#ifndef OMITGOOD
    printf("Calling good()...");
	//CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_01_good();
    printf("Finished good()");
#endif /* OMITGOOD */
    return 0;
}
