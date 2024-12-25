/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE369_Divide_by_Zero__int_fgets_divide_41.c
Label Definition File: CWE369_Divide_by_Zero__int.label.xml
Template File: sources-sinks-41.tmpl.c
*/
/*
 * @description
 * CWE: 369 Divide by Zero
 * BadSource: fgets Read data from the console using fgets()
 * GoodSource: Non-zero
 * Sinks: divide
 *    GoodSink: Check for zero before dividing
 *    BadSink : Divide a constant by data
 * Flow Variant: 41 Data flow: data passed as an argument from one function to another in the same source file
 *
 * */


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#define CHAR_ARRAY_SIZE (3 * sizeof(data) + 2)

#ifndef OMITBAD

static void badSink(int data)
{
    /* POTENTIAL FLAW: Possibly divide by zero */
int x;
	x=100/data;
        //printf("the result is %d \n",x);
	if (x>0){
	printf("OK");
}

}

void CWE369_Divide_by_Zero__int_fgets_divide_41_bad(char * inputBuffer)
{
    int data;
    /* Initialize data */
    data = -1;
    {
         data=(int) inputBuffer[1];
    }
    badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2BSink(int data)
{
    /* POTENTIAL FLAW: Possibly divide by zero */
int x;
	x=100/data;
        //printf("the result is %d \n",x);
	if (x>0){
	printf("OK");
}
}

static void goodG2B()
{
    int data;
    /* Initialize data */
    data = -1;
    /* FIX: Use a value not equal to zero */
    data = 7;
    goodG2BSink(data);
}

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2GSink(int data)
{
    /* FIX: test for a zero denominator */
    if( data != 0 )
    {
int x;
	x=100/data;
        //printf("the result is %d \n",x);
	if (x>0){
	printf("OK");
}

    }
    else
    {
        printf("This would result in a divide by zero");
    }
}

static void goodB2G(char * inputBuffer)
{
    int data;
    /* Initialize data */
    data = -1;
    {
         data=(int) inputBuffer[1];
    }
    goodB2GSink(data);
}

void CWE369_Divide_by_Zero__int_fgets_divide_41_good(char * data)
{
    goodB2G(data);
    goodG2B();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

int main(int argc, char * argv[])
{
	if (argc<2)
			return -1;

	int  fd1 = open(argv[1], O_RDONLY );
	char data;
	char input[4];
	read(fd1, input, 4);
	data=input[1];
#ifndef OMITGOOD
    printf("Calling good()...");
    CWE369_Divide_by_Zero__int_fgets_divide_41_good(input);
    printf("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printf("Calling bad()...");
    CWE369_Divide_by_Zero__int_fgets_divide_41_bad(input);
    printf("Finished bad()");
#endif /* OMITBAD */
    return 0;
}
