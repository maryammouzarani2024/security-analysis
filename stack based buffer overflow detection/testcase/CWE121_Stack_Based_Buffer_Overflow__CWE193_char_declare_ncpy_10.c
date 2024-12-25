/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_10.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE193.label.xml
Template File: sources-sink-10.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Point data to a buffer that does not have space for a NULL terminator
 * GoodSource: Point data to a buffer that includes space for a NULL terminator
 * Sink: ncpy
 *    BadSink : Copy string to data using strncpy()
 * Flow Variant: 10 Control flow: if(globalTrue) and if(globalFalse)
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

/* MAINTENANCE NOTE: The length of this string should equal the 10 */
#define SRC_STRING "AAAAAAAAAA"
#define globalTrue 1
#define globalFalse 0

#ifndef OMITBAD

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_10_bad(char * source)
{
    char * data;
    char dataBadBuffer[10];
    char dataGoodBuffer[10+1];
    if(globalTrue)
    {
        /* FLAW: Set a pointer to a buffer that does not leave room for a NULL terminator when performing
         * string copies in the sinks  */
        data = dataBadBuffer;
        data[0] = '\0'; /* null terminate */
    }
    {
        /* Copy length + 1 to include NUL terminator from source */
        /* POTENTIAL FLAW: data may not have enough space to hold source */
        strncpy(data, source, strlen(source) + 1);
     
		if (data[1]=='a'){        
	printf("OK");
}
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B1() - use goodsource and badsink by changing the globalTrue to globalFalse */
static void goodG2B1()
{
    char * data;
    char dataBadBuffer[10];
    char dataGoodBuffer[10+1];
    if(globalFalse)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printf("Benign, fixed string");
    }
    else
    {
        /* FIX: Set a pointer to a buffer that leaves room for a NULL terminator when performing
         * string copies in the sinks  */
        data = dataGoodBuffer;
        data[0] = '\0'; /* null terminate */
    }
    {
        char source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* POTENTIAL FLAW: data may not have enough space to hold source */
        strncpy(data, source, strlen(source) + 1);
        printf("%s",data);
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if statement */
static void goodG2B2()
{
    char * data;
    char dataBadBuffer[10];
    char dataGoodBuffer[10+1];
    if(globalTrue)
    {
        /* FIX: Set a pointer to a buffer that leaves room for a NULL terminator when performing
         * string copies in the sinks  */
        data = dataGoodBuffer;
        data[0] = '\0'; /* null terminate */
    }
    {
        char source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* POTENTIAL FLAW: data may not have enough space to hold source */
        strncpy(data, source, strlen(source) + 1);
        printf("%s",data);
    }
}

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_10_good()
{
    goodG2B1();
    goodG2B2();
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


#ifndef OMITBAD
    printf("Calling bad()...");
    CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_10_bad(buffer);
    printf("Finished bad()");
#endif /* OMITBAD */
#ifndef OMITGOOD
    printf("Calling good()...");
    CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_10_good();
    printf("Finished good()");
#endif /* OMITGOOD */
    return 0;
}

