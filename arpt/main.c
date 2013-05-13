#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <errno.h>
#include <sys/ioctl.h>

//Program Variables
char device[9];


//Ethernet II proto:
//1. Destination
char eth_dest[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
//2. Source
char eth_source[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
//3. ARP Code
char arpcode[2] = { 0x08, 0x06 };

//other vars
char current_mac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


//Address resolution proto:
unsigned char target_ip[4] = { 127, 0, 0, 1 };
unsigned char sender_ip[4] = { 192, 168, 0, 1 };



void error(const char *msg)
{
	printf("%s\n", msg);
	//check errorno
	if(errno == EACCES)
		printf("Try using SUDO.\n");
	exit(0);
}

//find the current mac
void update_mac()
{
	int s;
    struct ifreq buffer;

    s = socket(PF_INET, SOCK_DGRAM, 0);
	if(s == -1){
		error("Failed to open temp socket.");
	}

    memset(&buffer, 0x00, sizeof(buffer));

    strcpy(buffer.ifr_name, device);

    ioctl(s, SIOCGIFHWADDR, &buffer);

    close(s);

	memcpy(current_mac, buffer.ifr_hwaddr.sa_data, 6);
}

char* build_ethernet(char* buffer)
{
	memcpy(buffer, eth_dest, sizeof(char) * 6);
	memcpy(buffer+6, eth_source, sizeof(char) * 6);
	memcpy(buffer+6+6, arpcode, 2);
	return buffer+6+6+2;
}

char* build_arp(char* arp, char action)
{
	//hardware type: Ethernet
	arp[0] = 0x00;
	arp[1] = 0x01;
	//protocol type: IP
	arp[2] = 0x08;
	arp[3] = 0x00;
	//hardware size:
	arp[4] = 0x06;
	//protocol size:
	arp[5] = 0x04;
	//opcode: take from action(1 = request, 2 = reply)
	arp[6] = 0x00;
	arp[7] = action;


	//arp can be interpreted as follow:
	//[sender ip] is at [sender mac]

	//sender mac address
	memcpy(&arp[8], eth_source, 6);
	//sender ip
	memcpy(&arp[14], sender_ip, 4);
	//target mac
	memcpy(&arp[18], eth_dest, 6);
	//target ip
	memcpy(&arp[24], target_ip, 4);
	return arp+28;
}

void ascii_ip_to_array(char* source, char* target)
{
	int i = 0, c = 0, b = 0;
	char buffer[5] = { 0,0,0,0, '\0' };
	while(1){
		if(source[i] == '.'){
			target[c] = atoi(buffer);
			memset(buffer, 0, 4);
			b = 0;
			++c;
			++i;
			continue;
		}else if(source[i] == '\0'){
			target[c] = atoi(buffer);
			memset(buffer, 0, 4);
			b = 0;
			++c;
			break;
		}
		buffer[b] = source[i];
		++b;
		++i;
	}
}

void ascii_mac_to_array(char* source, char* target)
{
	if(!strcmp(source, "self")){
		update_mac();
		memcpy(target, current_mac, 6);
		return;
	}else if(!strcmp(source, "zero")){
		memset(target, 0, 6);
		return;
	}else if(!strcmp(source, "bcast")){
		memset(target, 0xFF, 6);
		return;
	}
	int i = 0,c = 0,b = 0;
	char buffer[6] = { 0,0,0,0,0,0 };
	while(1){
		if(source[i] == ':'){
			target[c] = strtoul(buffer,0,16);
			memset(buffer, 0, 6);
			++i;
			++c;
			b = 0;
			continue;
		}else if(source[i] == '\0'){
			target[c] = strtoul(buffer,0,16);
			return;
		}
		buffer[b] = source[i];
		++i;
		++b;
	}
}

//global socket stuff
int sockfd; struct sockaddr_ll socket_address;
void init_socket()
{
	sockfd = socket(AF_PACKET, SOCK_RAW, 0);
	if(sockfd == -1){
		error("Failed to open the socket.");
	}
	//---Initialize the socket address structure---//
	socket_address.sll_family = PF_PACKET;
	socket_address.sll_protocol = htons(ETH_P_IP);
	//index of network device. (eth1, wlan0, etc.)
	int devindex = if_nametoindex(device);
	if(devindex == 0)
		error("Failed to get device index.");
	socket_address.sll_ifindex = devindex;
	//arp hardware identifier
	socket_address.sll_hatype = ARPHRD_ETHER;
	//target is another host
	socket_address.sll_pkttype = PACKET_OTHERHOST;
	//addr len
	socket_address.sll_halen = ETH_ALEN;
	
	//this matters only for receiving(i guess)
	memcpy(	socket_address.sll_addr, eth_dest, sizeof(char)*6 );
	socket_address.sll_addr[6] = 0; // not used
	socket_address.sll_addr[7] = 0;

}

void send_arp_reply()
{
	
	int send_result = 0;

	char buffer[48];
	char *packet = buffer;	

	//---Build the packet---//
	packet = build_ethernet(buffer);
	build_arp(packet, 0x02);

	send_result = sendto(sockfd, buffer, 14+28, 0,
					(struct sockaddr*)&socket_address, sizeof(socket_address));

	printf("%i\n", send_result);
}

void send_arp_request(){
	char buffer[48]; int send_result = 0;
	char *packet = buffer;

	//---Build the packet---//
	packet = build_ethernet(buffer);
	build_arp(packet, 0x01);

	send_result = sendto(sockfd, buffer, 14+28, 0,
					(struct sockaddr*)&socket_address, sizeof(socket_address));

	printf("%i\n", send_result);
}



int main(int argc, char* argv[])
{
	if(argc < 2){
		printf("USAGE: arpt [dev] [action] [sender ip] [sender mac] [dest ip] [dest mac] [param 1]..[param n]\n");
		exit(0);
	}
	//get the device name
	strcpy(device, argv[1]);
	//get the action
	if(!strcmp(argv[2], "request")){
		ascii_ip_to_array(argv[3], sender_ip);
		ascii_mac_to_array(argv[4], eth_source);
		ascii_ip_to_array(argv[5], target_ip);
		ascii_mac_to_array(argv[6], eth_dest);
		init_socket();
		send_arp_request();
	}else if(!strcmp(argv[2], "reply")){
		ascii_ip_to_array(argv[3], sender_ip);
		ascii_mac_to_array(argv[4], eth_source);
		ascii_ip_to_array(argv[5], target_ip);
		ascii_mac_to_array(argv[6], eth_dest);
		init_socket();
		send_arp_reply();
	}else{
		printf("Unknown Command.\n");
		exit(0);
	}

	return 0;
}
