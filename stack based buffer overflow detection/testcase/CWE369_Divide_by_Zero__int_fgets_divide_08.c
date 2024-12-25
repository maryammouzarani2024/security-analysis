/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE369_Divide_by_Zero__int_fgets_divide_08.c
Label Definition File: CWE369_Divide_by_Zero__int.label.xml
Template File: sources-sinks-08.tmpl.c
*/
/*
 * @description
 * CWE: 369 Divide by Zero
 * BadSource: fgets Read data from the console using fgets()
 * GoodSource: Non-zero
 * Sinks: divide
 *    GoodSink: Check for zero before dividing
 *    BadSink : Divide a constant by data
 * Flow Variant: 08 Control flow: if(staticReturnsTrue()) and if(staticReturnsFalse())
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

/* The two function below always return the same value, so a tool
   should be able to identify that calls to the functions will always
   return a fixed value. */
static int staticReturnsTrue()
{
    return 1;
}

static int staticReturnsFalse()
{
    return 0;
}

#ifndef OMITBAD

void CWE369_Divide_by_Zero__int_fgets_divide_08_bad(char * inputBuffer)
{
    int data;
    /* Initialize data */
    data = -1;
    if(staticReturnsTrue())
    {
        {
           
                /* Convert to int */
                //data = atoi(inputBuffer);
				data=(int)inputBuffer[1];
           
        }
    }
    if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Possibly divide by zero */
int x;
	x=100/data;
        //printf("the result is %d \n",x);
	if (x>0){
	printf("OK");
}
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G1() - use badsource and goodsink by changing the second staticReturnsTrue() to staticReturnsFalse() */
static void goodB2G1(char * inputBuffer)
{
    int data;
    /* Initialize data */
    data = -1;
    if(staticReturnsTrue())
    {
        				data=(int)inputBuffer[1];

    }
    if(staticReturnsFalse())
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printf("Benign, fixed string \n");
    }
    else
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
            printf("This would result in a divide by zero \n");
        }
    }
}

/* goodB2G2() - use badsource and goodsink by reversing the blocks in the second if */
static void goodB2G2(char * inputBuffer)
{
    int data;
    /* Initialize data */
    data = -1;
    if(staticReturnsTrue())
    {
       				data=(int)inputBuffer[1];

    }
    if(staticReturnsTrue())
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
            printf("This would result in a divide by zero \n");
        }
    }
}

/* goodG2B1() - use goodsource and badsink by changing the first staticReturnsTrue() to staticReturnsFalse() */
static void goodG2B1()
{
    int data;
    /* Initialize data */
    data = -1;
    if(staticReturnsFalse())
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printf("Benign, fixed string \n");
    }
    else
    {
        /* FIX: Use a value not equal to zero */
        data = 7;
    }
    if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Possibly divide by zero */
int x;
	x=100/data;
        //printf("the result is %d \n",x);
	if (x>0){
	printf("OK");
}

		}
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the first if */
static void goodG2B2()
{
    int data;
    /* Initialize data */
    data = -1;
    if(staticReturnsTrue())
    {
        /* FIX: Use a value not equal to zero */
        data = 7;
    }
    if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Possibly divide by zero */
	int x;
	x=100/data;
        //printf("the result is %d \n",x);
	if (x>0){
	printf("OK");
}

		}
}

void CWE369_Divide_by_Zero__int_fgets_divide_08_good(char * data)
{
    goodB2G1(data);
    goodB2G2(data);
    goodG2B1();
    goodG2B2();
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
    CWE369_Divide_by_Zero__int_fgets_divide_08_good(input);
    printf("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printf("Calling bad()...");
    CWE369_Divide_by_Zero__int_fgets_divide_08_bad(input);
    printf("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

