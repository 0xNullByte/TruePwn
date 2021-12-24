/*
	@ gcc version 10.2.1  (Debian 10.2.1-6) 
	 gcc -fno-stack-protector -z execstack -no-pie TruePwn.c -o TruePwn.out
*/

#include <stdio.h>

int Sum(int x, int y){
	return x + y;
}

int hideFunc(){
	system("echo TruePwn!");
	return 1;
}

int main(int argc, char* argv[])
{
	char BUF[700];
	printf("Enter your name:\n");
	gets(BUF); 

	printf("Hello : %s", &BUF);	
}
