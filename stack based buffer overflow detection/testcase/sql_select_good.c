/* This software was developed at the National Institute of Standards and
 * Technology by employees of the Federal Government in the course of their
 * official duties. Pursuant to title 17 Section 105 of the United States
 * Code this software is not subject to copyright protection and is in the
 * public domain. NIST assumes no responsibility whatsoever for its use by
 * other parties, and makes no guarantees, expressed or implied, about its
 * quality, reliability, or any other characteristic.

 * We would appreciate acknowledgement if the software is used.
 * The SAMATE project website is: http://samate.nist.gov
*/
#include </usr/include/mysql/mysql.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

int main(int argc, char *argv[]) 
{
   MYSQL *conn;
   MYSQL_RES *res;
   MYSQL_ROW row;

   char *server = "localhost";
   char *user = "root";
   char *password = "123";
   char *database = "uni";
   

		if (argc<2)
		return -1;

	int  fd1 = open(argv[1], O_RDONLY);

	char input[5];
	strcpy(input,"");
	read(fd1, input, 4);
	//printf("the input is %s\n",input);
   conn = mysql_init(NULL);
   
   /* Connect to database */
   if (!mysql_real_connect(conn, server,
         user, password, database, 0, NULL, 0)) {
      fprintf(stderr, "%s********\n", mysql_error(conn));
      return 0;
   }

   /* send SQL query */
   char query[512];
   char *fmtString = "SELECT * FROM class WHERE sub LIKE '%s';";
   
   /* No more buffer overflow */
	if ((strlen(input) + strlen(fmtString)) > 512){
		printf("The entry is too long...\n");
		return 0;		
	}
	
char param_escaped[6];
	strcpy(param_escaped,"");
	// sanitize the query string
	mysql_real_escape_string(conn, param_escaped, input, strlen(input));
	sprintf(query,fmtString,param_escaped);
	//printf("the escaped is %s\n",param_escaped);
	//	printf("query is %s\n",query);
	
//if (query[37]=='P'){
	
	if (mysql_query(conn, query)) {
	  fprintf(stderr, "%s\n", mysql_error(conn));
	  return 0;
	}
	
//}
	res = mysql_use_result(conn); 
	

if (res){
 printf("OK \n");
}

		//	printf("we have results\n");
	/* output fields 1 and 2 of each row */
	while ((row = mysql_fetch_row(res)) != NULL)
	  printf("%s %s\n", row[0], row[1]);
		//printf(" results printed\n");
	/* Release memory used to store results and close connection */
	mysql_free_result(res);

if (query[38]=='z'){
	mysql_close(conn);
}
	return 0;
}

