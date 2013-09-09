/************************************************************************
* Narseo Vallina-Rodriguez. University of Cambridge. 2013				*
* narseo@gmail.com                                                      *
*************************************************************************/


#include <stdio.h>    
#include <sys/socket.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <string.h>
#define EXIT_FAILURE -1
#define IF_NAME "pdp0"
#define htons(A) ((((unsigned short)(A) & 0xff00) >> 8) | \
(((unsigned short)(A) & 0x00ff) << 8))


int main()
{

    int s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if(s == -1)
	{
		perror("Error 20001\nCould not create RAW Ethernet Socket!\n");
		return(EXIT_FAILURE);
	}

	//obtaining IF index
	struct ifreq ifr;
	strncpy(ifr.ifr_name,IF_NAME,16);
	if(ioctl(s,SIOCGIFINDEX,&ifr) != 0)
	{
		printf("Error 20009\nUnable to obtain IF index!\n");
		return(EXIT_FAILURE);
	}
	//SOCKET.IF_INDEX = ifr.ifr_ifindex;

/*
	//obtaining MAC address
	strncpy(ifr.ifr_name,IF_NAME,16);
	if(ioctl(SOCKET_ID,SIOCGIFHWADDR,&ifr) != 0)
	{
		printf("Error 20010\nUnable to obtain MAC address!\n");
		return(EXIT_FAILURE);
	}
    */
	//memcpy(SOCKET.MY_MAC,ifr.ifr_hwaddr.sa_data,6);

	//socket config
	struct sockaddr_ll socket_address = {0};
	socket_address.sll_family = AF_PACKET;
	socket_address.sll_protocol = htons(ETH_P_ALL);
	socket_address.sll_ifindex = ifr.ifr_ifindex;
	//socket_address.sll_pkttype = PACKET_OTHERHOST|PACKET_BROADCAST|PACKET_MULTICAST|PACKET_HOST;
	//socket_address.sll_halen = ETH_ALEN;
	//socket_address.sll_hatype = 0x0000; 

	//bind socket to NIC by IF_INDEX
	int bind_res = bind(s,(struct sockaddr*)&socket_address,sizeof(socket_address));
	if(bind_res == -1)
	{
		printf("Error 20008\nCould not bind Socket to Device! %d", errno);
		return(EXIT_FAILURE);
	}

/*
	//set promiscious mode manually
	strncpy(ifr.ifr_name,IF_NAME,16);
	ioctl(SOCKET_ID,SIOCGIFFLAGS,&ifr);
	//ifr.ifr_flags |= IFF_ALLMULTI;
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(SOCKET_ID,SIOCSIFFLAGS,&ifr);
    */

    do
    {

        struct sockaddr_ll addr;
        socklen_t addr_len = sizeof(addr);
        char packet[65536];
        int packetsize = sizeof(packet);
        int length = recvfrom(s, packet, packetsize, 0, (struct sockaddr*)&addr, &addr_len);
        if (length <= 0) {
          perror("recvfrom failed");
          return(0);
        }
int i=0;
		for (i=0; i<length; i++){
			printf("%02x ", packet[i]);
		}
		printf("\n");

        if (addr.sll_pkttype == PACKET_OUTGOING) continue; // drop it
        if (length > 100) printf("Got packet! %d bytes\n", length);
    }
    while (1);


}

