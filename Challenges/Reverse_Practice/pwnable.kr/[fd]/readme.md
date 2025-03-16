## [fd]
So this challenge was so easy 
firtst this is the code given 

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
	if(argc<2){
		printf("pass argv[1] a number\n");
		return 0;
	}
	int fd = atoi( argv[1] ) - 0x1234;
	int len = 0;
	len = read(fd, buf, 32);
	if(!strcmp("LETMEWIN\n", buf)){
		printf("good job :)\n");
		system("/bin/cat flag");
		exit(0);
	}
	printf("learn about Linux file IO\n");
	return 0;

}
```

so in this code this part is vuln
```
	len = read(fd, buf, 32);
```

so when seen if fd is made 0 then the value could be taken as a input and solved
```
	int fd = atoi( argv[1] ) - 0x1234;
```

hence with this we could say that this input coudle be manupulated to 
4660 - 0x1234 =0
this will replace the read addr as 0 and it could be elemenated
stdinput is activated 
1-stdoutput
2-stderr
