/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_loop_41.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE193.label.xml
Template File: sources-sink-41.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Point data to a buffer that does not have space for a NULL terminator
 * GoodSource: Point data to a buffer that includes space for a NULL terminator
 * Sink: loop
 *    BadSink : Copy array to data using a loop
 * Flow Variant: 41 Data flow: data passed as an argument from one function to another in the same source file
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

#ifndef OMITBAD

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_loop_41_badSink(char * data, char * source)
{
    {
        size_t i, sourceLen;
        sourceLen = strlen(source);
        /* Copy length + 1 to include NUL terminator from source */
        /* POTENTIAL FLAW: data may not have enough space to hold source */
        for (i = 0; i < sourceLen + 1; i++)
        {
            data[i] = source[i];
        }
		if (data[1]=='a'){        
	printf("OK");
}

    }
}

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_loop_41_bad(char * source)
{
    char * data;
    char dataBadBuffer[10];
    char dataGoodBuffer[10+1];
    /* FLAW: Set a pointer to a buffer that does not leave room for a NULL terminator when performing
     * string copies in the sinks  */
    data = dataBadBuffer;
    data[0] = '\0'; /* null terminate */
    CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_loop_41_badSink(data,source);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_loop_41_goodG2BSink(char * data)
{
    {
        char source[10+1] = SRC_STRING;
        size_t i, sourceLen;
        sourceLen = strlen(source);
        /* Copy length + 1 to include NUL terminator from source */
        /* POTENTIAL FLAW: data may not have enough space to hold source */
        for (i = 0; i < sourceLen + 1; i++)
        {
            data[i] = source[i];
        }
        printf("%s",data);
    }
}

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
    CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_loop_41_goodG2BSink(data);
}

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_loop_41_good()
{
    goodG2B();
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

#ifndef OMITGOOD
    printf("Calling bad()...");
    CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_loop_41_bad(buffer);
    printf("Finished bad()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printf("Calling good()...");
    CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_loop_41_good();
    printf("Finished good()");
#endif /* OMITBAD */
    return 0;
}

