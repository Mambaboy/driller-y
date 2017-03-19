#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char * argv[])
{
	char buf[2]={0};
	read(0, buf, 1);
	int c=buf[0];
	switch (c)
	{
		case 'a':
			printf("find a\n");
			break;
		case 'b':
			printf("find b\n");
			break;
		case 'z':
			printf ("find z\n");
			break;
		default:
			printf("hahaha\n");
					
	}
	return 0;
}