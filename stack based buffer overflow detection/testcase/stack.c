/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cpy_01.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__src.label.xml
Template File: sources-sink-01.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Initialize data as a large string
 * GoodSource: Initialize data as a small string
 * Sink: cpy
 *    BadSink : Copy data to string using strcpy
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

#ifndef OMITBAD

void bad(char * data)

    {
        char source[100];
	//if (data[2]=='b'){
        /* POTENTIAL FLAW: Possible buffer overflow if the size of data is less than the length of source */
      //  snprintf(source, strlen(data), "%s", data);
	strcpy(source,data);
	if (source[1]=='a')
        printf("ok");
//}
    }

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * data;
    char dataBuffer[100];
    data = dataBuffer;
    /* FIX: Initialize data as a small buffer that as small or smaller than the small buffer used in the sink */
    memset(data, 'A', 50-1); /* fill with 'A's */
    data[50-1] = '\0'; /* null terminate */
    {
        char dest[50] = "";
        /* POTENTIAL FLAW: Possible buffer overflow if data is larger than dest */
        strcpy(dest, data);
	if (dest[1]=='q'){
        printf("OK");
	    }
	}
}

void CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cpy_01_good(char * data)
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
    /* seed randomness */
   // srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printf("Calling good()...");
    //CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cpy_01_good(buffer);
    printf("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printf("Calling bad()...");
    bad(buffer);
    printf("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

