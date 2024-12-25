/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE476_NULL_Pointer_Dereference__binary_if_01.c
Label Definition File: CWE476_NULL_Pointer_Dereference.pointflaw.label.xml
Template File: point-flaw-01.tmpl.c
*/
/*
 * @description
 * CWE: 476 NULL Pointer Dereference
 * Sinks: binary_if
 *    GoodSink: Do not check for NULL after the pointer has been dereferenced
 *    BadSink : Check for NULL after a pointer has already been dereferenced
 * Flow Variant: 01 Baseline
 *
 * */
 #include <fcntl.h>
#include <unistd.h>


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#ifndef OMITBAD

void CWE476_NULL_Pointer_Dereference__binary_if_01_bad(unsigned int data)
{
    {

		char substr[10];
char *t;
//char  a[80], d[10];
//		printf ("the result is %d \n",data);	
	if (data == substr)
{
	 t=(char *)substr - data;
	printf ("the result is %s \n",t[0]);

}			
	//strcpy(a,"123456789012345678901234567890123456789012345678901234567890123456789");
//strcpy(d,"1256789");
	//printf ("the result is %x \n",substr);
	
	//printf ("the result is %s \n",a[c]);	
 //if (d[c]=='5'){
//printf("OK");
//}
 
        /* FIX: Use && in the if statement so that if the left side of the expression fails then
         * the right side will not be evaluated */
//      if ((twoIntsStructPointer != NULL) & (*twoIntsStructPointer == 5))
        {
            printf("intOne == 5");
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

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
	char input[6] = {0,};
//	int  fd1 = open(argv[1], O_RDONLY );
	read(fd1, input,6);
	data=input[1];
	/* POTENTIAL FLAW: Use a value input from the console */
	//unsigned char data=input[1];
    /* seed randomness */
  //  srand( (unsigned)time(NULL) );
int b;	
b=atoi(input);	
	//printf ("the result is %s \n",input);		
    printf("Calling bad()...");

     
    CWE476_NULL_Pointer_Dereference__binary_if_01_bad(*(int*)input);
    printf("Finished bad()");
/* OMITBAD */
    return 0;
}

