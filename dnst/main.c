#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
     
#define BUFLEN 2048
#define PORT 53
#define SERVER "192.168.0.1"

void error(const char* msg)
{
    printf("%s\n", msg);
    exit(0);
} 

char* build_dns(char* buffer, short trans_id, char* name)
{
	int name_len = strlen(name), i = 0, b = 0, j = 1;
	//transaction id
	buffer[0] = *(char*)&trans_id;
	buffer[1] = ((char*)&trans_id)[1];
	
	//Flags
	buffer[2] = 0x01;
	buffer[3] = 0x00;
	
	//Questions
	buffer[4] = 0x00;
	buffer[5] = 0x01;
	
	//Answer RRs
	buffer[6] = 0x00;
	buffer[7] = 0x00;
	
	//Authority RRs:
	buffer[8] = 0x00;
	buffer[9] = 0x00;
	
	//Additional RRs
	buffer[10] = 0x00;
	buffer[11] = 0x00;
	
	//copy name
	j = 0;
	for(i = 0; i <= name_len; ++i)
	{
		if(name[i] == '.' || name[i] == '\0')
		{
			buffer[12+b] = j;
			j = 0;
			b = i+1;
		}else
		{
			buffer[12+b+j+1] = name[i];
			++j;
		}
	}
	name_len+=1;
	buffer[12+name_len] = 0x00; //null terminate
	
	buffer[12+name_len+1] = 0x00;
	buffer[12+name_len+2] = 0x01;
	
	buffer[12+name_len+3] = 0x00;
	buffer[12+name_len+4] = 0x01;
	
	return buffer+12+5+name_len;
}


enum prog_action
{
	P_REQUEST,
	P_REPLY,
	P_ERROR
};
struct arg_flags
{
	char action;
};

int main(int argc, char **argv)
{
        struct sockaddr_in si_other;
		int s, i, slen=sizeof(si_other), sent;
		char buf[BUFLEN], *end;
		char message[BUFLEN];
	 
		if ( (s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		{
		    error("socket");
		}
	 
		memset((char *) &si_other, 0, sizeof(si_other));
		si_other.sin_family = AF_INET;
		si_other.sin_port = htons(PORT);
		 
		if (inet_aton(SERVER , &si_other.sin_addr) == 0)
		{
		    fprintf(stderr, "inet_aton() failed\n");
		    exit(1);
		}
        
        end = build_dns(buf, 25434, "linuxmint.com");
        
        sent = sendto(s, buf, end-buf, 0, (struct sockaddr*)&si_other, sizeof(si_other));
        printf("%i\n", sent);
        return 0;
}
