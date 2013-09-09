/************************************************************************
* Narseo Vallina-Rodriguez. University of Cambridge. 2013				*
* narseo@gmail.com                                                      *
*************************************************************************/


#include <sys/time.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>                                                                  
#include <string.h>     


#define LOGGER_BUFLEN 1024
#define PORT 9930
#define INITIAL_SLEEP_TIME 40


/**************************
* function diep
*
* usage: exits process in case of error
**************************/
void diep(char *s)
{
	perror(s);
	exit(1);
}



int main(void)
{
	sleep(INITIAL_SLEEP_TIME);
	struct timeval tv; //time for logging

	struct sockaddr_in si_me, si_other;
	int s, i, slen=sizeof(si_other);
	char buf[LOGGER_BUFLEN];
	if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1){
		diep("LOGGER Error: socket");
	}
	bzero((char *) &si_me, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(PORT);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(s, (struct sockaddr *) &si_me, sizeof(si_me))==-1){
    diep("LOGGER Error: bind");
	}

	//Open file
	FILE *fp;
	fp = fopen("/sdcard/ril_log", "a+");

	int nbytes =0;
		
	while(1) {
 		if ((nbytes=recvfrom(s, buf, LOGGER_BUFLEN, 0, (struct sockaddr *) &si_other, &slen))==-1){
 			diep("LOGGER Error: recvfrom()");
		}
		//Has to include "%s". GCC is warning about the fact that the program will try to read an argyment that
		//hasn't been defined
		gettimeofday(&tv, NULL);
		fprintf(fp, "%ld.%ld,%s", tv.tv_sec, tv.tv_usec, buf);
		fflush(fp);
		memset(buf, 0, sizeof(buf));	
	}
	close(s);
	fclose(fp);
	return 0;
}
