/************************************************************************
* Narseo Vallina-Rodriguez. University of Cambridge. 2013				*
* narseo@gmail.com                                                     	*
*************************************************************************/

#include "spectrumutils.h"

int main()
{
	sleep(INITIAL_SLEEP_TIME);
	//lock
	pthread_mutex_init(&mutex, NULL);
	//Initialize to null the procList head Pointer
	headListPtr = NULL;
	
	//File descriptors, etc
	int tap_fd, option;
	int flags = IFF_TUN;
	int maxfd;
	uint16_t nread, nwrite;
	int optval = 1;
	strcpy(tun_name, "tun1");
	char packet[4096];
	int packetsize = sizeof(packet);

	//Used to send data to the logger
	char log_buffer [1024];
	char dAddrBuf[INET_ADDRSTRLEN];
	char sAddrBuf[INET_ADDRSTRLEN];

	//Register file descriptor
	if ( (tap_fd = tun_alloc(tun_name, flags | IFF_NO_PI)) < 0 ) {
		my_err("Error connecting to tun/tap interface %s!\n", tun_name);
		exit(1);
	}
	do_debug("Successfully connected to interface %s\n", tun_name);

	int net_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	do_debug("Socket created\n");
	if(net_fd == -1)
	{
		perror("Error 20001\nCould not create RAW Ethernet Socket!\n");
		return(EXIT_FAILURE);
	}
	//obtaining IF index
	struct ifreq ifr;
	strncpy(ifr.ifr_name,IF_NAME,16);
	if(ioctl(net_fd,SIOCGIFINDEX,&ifr) != 0)
	{
		my_err("Error. Unable to obtain IF index!\n");
		return(EXIT_FAILURE);
	}
	//I want IP address attached to pdp0
	int ifIndex = ifr.ifr_ifindex;
	strncpy(ifr.ifr_name, IF_NAME, IFNAMSIZ-1);
	ioctl(net_fd, SIOCGIFADDR, &ifr);
	// display result
  	do_debug("Local IP addr %s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

  	//socket config
	struct sockaddr_ll socket_address = {0};
  	socket_address.sll_family = AF_PACKET;
  	socket_address.sll_protocol = htons(ETH_P_IP);
  	socket_address.sll_ifindex = ifIndex;
  	socket_address.sll_hatype = 512;

	//socket_address.sll_pkttype = PACKET_OTHERHOST|PACKET_BROADCAST|PACKET_MULTICAST|PACKET_HOST;
	//socket_address.sll_halen = ETH_ALEN;

  	do_debug("Socket config done\n");
  	//bind socket to NIC by IF_INDEX
  	int bind_res = bind(net_fd,(struct sockaddr*)&socket_address,sizeof(socket_address));
  	do_debug("Socket bind()\n");
  	if(bind_res == -1)
  	{
		do_debug("Error %d. Could not bind Socket to Device! ", errno);
		return(EXIT_FAILURE);
  	}
	maxfd = (tap_fd > net_fd)?tap_fd:net_fd;




	int direction = 0;
	//-1 Outgoing
	//+1 Incoming
	do
  	{
		int ret;
		struct timeval tv; //time for logging

		fd_set rd_set;
		FD_ZERO(&rd_set);
		FD_SET(tap_fd, &rd_set); 
		FD_SET(net_fd, &rd_set);
		ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
		if (ret < 0 && errno == EINTR){
			continue;
		}
		if (ret < 0) {
			perror("Error select()");
			exit(1);
		}
		/*
		*Define socket to write in
		*/
		struct sockaddr_ll addr;
		socklen_t addr_len = sizeof(addr);

		if(FD_ISSET(tap_fd, &rd_set)){
			/* data from tun/tap: just read it from FD and write it to the network */
			//Outgoing traffic. 
			
			direction = -1;
			time_t curtime;
			gettimeofday(&tv, NULL);
			curtime=tv.tv_sec;
			
     		nread = cread(tap_fd, packet, packetsize);
			do_debug("\n--------------------\nREADING %d BYTES OUTGOING TRAFFIC\n", nread);
 
			//Get ip header
			struct iphdr *ip = (struct iphdr *) packet;

			if (DEBUG){
				do_debug("\nSOURCE IP: ");
				print_ip(ip->saddr);
				do_debug("\nDST IP: ");
				print_ip(ip->daddr);
			}

			//Replace the source IP
			ip->saddr = (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr;
			//Set IP checksum to 0
			ip->check = 0; 
			//Define packet as "forwardable" by default. Filter the ones we want to remove
			int fwd2net = 1;

			if (DEBUG){
				do_debug("\nNATTING. NEW S_ADDR: ");
				print_ip(ip->saddr);
			}

			inet_ntop(AF_INET, &ip->daddr, dAddrBuf, sizeof(dAddrBuf));
			inet_ntop(AF_INET, &ip->saddr, sAddrBuf, sizeof(sAddrBuf));



			//Change Upper layer prots later
			switch(ip->protocol){
				case 1: 
					do_debug("PROTOCOL: ICMP");
					memset(log_buffer, 0, sizeof(log_buffer));
					sprintf(log_buffer, "ICMP,%d,%d,%s,%s,%d,%d\n",direction, fwd2net, sAddrBuf, dAddrBuf,ip->protocol,ntohs(ip->tot_len));
					print_log(log_buffer, sizeof(log_buffer));

					break;
				case 6: 
					do_debug("PROTOCOL: TCP\n");		

					struct tcphdr *tcp = (struct tcphdr *) (ip+1);
					tcp->check = 0; /* Checksum field has to be set to 0 before checksumming */		
			
					if (tcp->rst!=0){
						fwd2net = 0; 
						break;
					}

					//http://developerweb.net/viewtopic.php?id=3171
					//Calculate pseudo header
					tcp_phdr_t pseudohdr;  
					int tcpSize=nread-sizeof(*ip);
					

					/* TCP Pseudoheader + TCP actual header used for computing the checksum */
  					char tcpcsumblock[ 4096 ];
					memset(&pseudohdr,0,sizeof(tcp_phdr_t));

				  	/* Fill the pseudoheader so we can compute the TCP checksum*/
					//TODO: Check if it can be optimising. Force them.
					pseudohdr.src = ip->saddr;
					pseudohdr.dst = ip->daddr;
					pseudohdr.zero = 0;
					pseudohdr.protocol = ip->protocol;
					pseudohdr.tcplen = htons(nread-sizeof(*ip));
					//Copy header and pseudoheader to a buffer to compute the checksum 
					memcpy(tcpcsumblock, &pseudohdr, sizeof(tcp_phdr_t));   
					memcpy(tcpcsumblock+sizeof(tcp_phdr_t),(ip+1), tcpSize);
					tcp->check = in_cksum((unsigned short *)(tcpcsumblock), sizeof(tcp_phdr_t)+tcpSize); 
					do_debug("COMPUTED TCP CHECKSUM %d",tcp->check);

					//PORT RESOLUTION
					char * procName = searchTcpProcName (ntohs(tcp->source));

					if (procName == NULL){	
						int rc;
                        			pthread_t thread;
			                        ThreadParam mTmpFlow;

						printf("Not identified port = %d in any process. Launching thread.\n", ntohs(tcp->source));
						mTmpFlow.transpProto = TCP;
						mTmpFlow.localPort = ntohs(tcp->source);
						do_debug("Structure: proto=%d, port=%d\n", mTmpFlow.transpProto, mTmpFlow.localPort);
						//Create thread	
						rc = pthread_create(&thread, NULL, portResolution, (void *) &mTmpFlow);
						if (rc){
							printf("Error creating thread\n");
							exit(-1); //Shouldn't be like that
						
						}
						procName="unknown";
					}
				
			
		


					//Process if HTTP traffic
					if ((ntohs(tcp->dest)==HTTP_PORT) || (ntohs(tcp->dest)==HTTP_PORT_ALT)){

	                                                //printf("OUTGOING Offset %d - (ntohs) %d\n", tcp->doff, ntohs(tcp->doff));

							/*TODO Parse HTTP*/
							//USE https://github.com/joyent/http-parser
							//printf("************************************\nHTTP\n");
							int dataoffset = tcp->doff;


							if (dataoffset%4!=0){
								dataoffset = dataoffset + (4-dataoffset%4);
							}
							int payload = nread -sizeof(*ip) - sizeof(*tcp) - dataoffset;

							//printf("--> HTTP -- TOTAL: %d, IP: %d, TCP %d. Offset %d/Adjusted Offset %d, Estimated TCP Payload (Adjusted): %d\n", nread, sizeof(*ip), sizeof(*tcp), tcp->doff, dataoffset, payload);

							if (payload >= MIN_HTTP_HEADER){
							//	printf("* Obtaining payload\n");
								//It assumes that if the tcp packet has more than 64 bytes,
								//then we have some real flesh in the payload and not just the header. 
								//If so, Print 64 bytes tcp payload if HTTP on the buffer to send it to the logger
								/*
								TODO: When writing the first 64 bytes of the TCP payload, it looks like it also prints something (around 12 bytes) from
								the TCP header*/
								if (payload > HTTP_HEADER_READ_SIZE){
									payload = HTTP_HEADER_READ_SIZE;
								}
                                                                char tcpPayload[ payload ];

								int jumpTo = sizeof(*ip)+sizeof(*tcp)+dataoffset+2;
							//	printf("* Bytes to ignore: %d\n", jumpTo);
//								printf("* BUFFER: %s\n", packet+(jumpTo));
	
        							memset(tcpPayload, 0, sizeof(tcpPayload));
								memcpy(tcpPayload, &packet[jumpTo], payload-1);

								printf("\n\n--------------\n");
								printf("* PAYLOAD OUTGOING (size %d):\n %s\n", sizeof(tcpPayload), tcpPayload);
								printf("-----------------\n\n");


							/*
							int tcpPayloadSize = nread-sizeof(*ip)-sizeof(*tcp);
							if (DEBUG) printf("Payload %d\n - Total %d IPHDR %d, TCPHDR %d", tcpPayloadSize,nread, sizeof(*ip), sizeof(*tcp));
  						char tcpPayload[ 4096 ];
							memcpy(tcpPayload, packet+(nread-tcpPayloadSize), tcpPayloadSize);
							//Todo: needs to return a char * with the data to embed on the log_buffer  
							parseHTTPRequest(tcpPayload, tcpPayloadSize);
							*/

								sprintf(log_buffer, "HTTP,%s,%d,%d,%s,%s,%d,%d,%d,%d, %d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n***%s\n***\n",procName,direction, fwd2net, sAddrBuf, dAddrBuf,ip->protocol,ntohs(ip->tot_len), ntohs(tcp->source), ntohs(tcp->dest), ntohs(tcp->seq), tcpSize, tcp->window, tcp->res1, tcp->doff, tcp->fin, tcp->syn, tcp->rst, tcp->psh, tcp->ack, tcp->urg, tcp->ece, tcp->cwr, tcpPayload);
								print_log(log_buffer, sizeof(log_buffer));
							}
							else{//Do not print 64 bytes from tcp payload
								sprintf(log_buffer, "HTTP,%s,%d,%d,%s,%s,%d,%d, %d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",procName,direction, fwd2net, sAddrBuf, dAddrBuf,ip->protocol,ntohs(ip->tot_len), ntohs(tcp->source), ntohs(tcp->dest), ntohs(tcp->seq),tcpSize, tcp->window, tcp->res1, tcp->doff, tcp->fin, tcp->syn, tcp->rst, tcp->psh, tcp->ack, tcp->urg, tcp->ece, tcp->cwr);
								print_log(log_buffer, sizeof(log_buffer));
							}
					}
					else{
						printf("Standard TCP\n");
						//Standard TCP traffic 
						memset(log_buffer, 0, sizeof(log_buffer));
						sprintf(log_buffer, "TCP,%s,%d,%d,%s,%s,%d,%d,%d,%d,%d,%d, %d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",procName,direction,fwd2net, sAddrBuf, dAddrBuf,ip->protocol,ntohs(ip->tot_len), ntohs(tcp->source), ntohs(tcp->dest), ntohs(tcp->seq), tcpSize, tcp->window, tcp->res1, tcp->doff, tcp->fin, tcp->syn, tcp->rst, tcp->psh, tcp->ack, tcp->urg, tcp->ece, tcp->cwr);
						print_log(log_buffer, sizeof(log_buffer));
					}
					break;
				case 17: 
					do_debug("PROTOCOL: UDP\n");
					struct udphdr *udp = (struct udphdr *) (ip+1);
					udp->check=0;


                                        //***************************TODO****************************
                                        /*
//Get name resolution
					mTmpFlow.transpProto = UDP;
                                        mTmpFlow.localPort = ntohs(udp->source);
                                        printf("Structure: proto=%d, port=%d\n", mTmpFlow.transpProto, mTmpFlow.localPort);

                                        //Create thread
                                        printf("Initializing Thread\n");
                                        rc = pthread_create(&thread, NULL, portResolution, (void *) &mTmpFlow);

                                        if (rc){
                                                printf("Error creating thread\n");
                                                exit(-1); //Shouldn't be like that
                                        }
					*/
                                        //***************************TODO****************************

					if (ntohs(udp->dest)== DNS_PORT){
						memset(log_buffer, 0, sizeof(log_buffer));
						sprintf(log_buffer, "DNSLOOKUP,%d,%d,%s,%s,%d,%d,%d,%d,%d\n",direction, fwd2net, sAddrBuf, dAddrBuf, ip->protocol, ntohs(ip->tot_len), ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len));
						print_log(log_buffer, sizeof(log_buffer));

					}
					else{
						memset(log_buffer, 0, sizeof(log_buffer));
						sprintf(log_buffer, "UDP,%d,%d,%s,%s,%d,%d,%d,%d,%d\n",direction, fwd2net, sAddrBuf, dAddrBuf, ip->protocol, ntohs(ip->tot_len), ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len));
						print_log(log_buffer, sizeof(log_buffer));					
					}
					break;
				default: do_debug("PROTOCOL: OTHER. Nothing to do (yet)");
					memset(log_buffer, 0, sizeof(log_buffer));
					sprintf(log_buffer, "UNKNOWN,%d,%d,%s,%s,%d,%d\n",direction,fwd2net, sAddrBuf, dAddrBuf,ip->protocol,ntohs(ip->tot_len));
					print_log(log_buffer, sizeof(log_buffer));
					break;		
			}		


			//Calculate IP header as standard says. Set to 0 before re-calculating
			if (fwd2net){
				ip->check = 0; 
				ip->check=cksum(ip, 4*ip->ihl);
		 		socket_address.sll_pkttype = PACKET_OUTGOING; 
				int send = sendto(net_fd, packet, nread,0, (struct sockaddr*)&socket_address, sizeof(socket_address));
				do_debug("WRITING %d BYTES TO THE CELLULAR INTERFACE\n", send);
			}

			
    }

		if(FD_ISSET(net_fd, &rd_set)){
			//Read from socket and write on the tun FD
			direction = 1;
			time_t curtime;
			gettimeofday(&tv, NULL);
			curtime=tv.tv_sec;
			char buffer[30];
			strftime(buffer, 30, "%m-%d-%Y %T", localtime(&curtime));
			
			int nread = recvfrom(net_fd, packet, packetsize, 0, (struct sockaddr*)&addr, &addr_len);
			if (nread <= 0) {
		  	perror("recvfrom failed");
		  	return(0);
			}
			do_debug("\n--------------------\nREADING  %d INCOMING TRAFFIC\n", nread);

			//Get ip header
			struct iphdr *ip = (struct iphdr *) packet;
			if (DEBUG){
				do_debug("SOURCE IP: ");
				print_ip(ip->saddr);
				do_debug("DST IP: ");
				print_ip(ip->daddr);
				do_debug("INITIAL TTL: %d",ip->ttl);
			}
			//Modify TTL just in case
			ip->ttl = 7;

			inet_ntop(AF_INET, &ip->daddr, dAddrBuf, sizeof(dAddrBuf));
			inet_ntop(AF_INET, &ip->saddr, sAddrBuf, sizeof(sAddrBuf));


			//Reverse natting
			ip->daddr = inet_addr("10.0.1.1");
			if (DEBUG){
				do_debug("NATTING. NEW DESTINATION IP: ");
				print_ip(ip->daddr);
			}
			ip->check = 0; 
			//Used to see whether the packet has to be forwarded or not. 
			//We are not forwarding ICMP ones for instance
			

			int fwPacket = 0;
			switch(ip->protocol){
				/*TODO: Check the IP congestion flag! Maybe we can use it to send feedback between client and server*/
				case 1: 
					do_debug("INCOMING PROTOCOL: ICMP\n");
					memset(log_buffer, 0, sizeof(log_buffer));
					sprintf(log_buffer, "ICMP,%d,%d,%s,%s,%d,%d\n",direction, fwPacket, sAddrBuf, dAddrBuf,ip->protocol,ntohs(ip->tot_len));
					print_log(log_buffer, sizeof(log_buffer));
					//icmp is not forwarded. It is a l4 protocol so there's no app 
					//listening for that so as it arrives to the handset you already 
					//get it. If you forward, you get a dup
					break;
				case 6: 
					do_debug("INCOMING PROTOCOL: TCP\n");
					struct tcphdr *tcp = (struct tcphdr *) (ip+1);
					tcp->check = 0;
					tcp_phdr_t pseudohdr;

					int tcpSize=nread-sizeof(*ip);
					/* TCP Pseudoheader + TCP actual header used for computing the checksum */
  					char tcpcsumblock[ 4096 ];	
					memset(&pseudohdr,0,sizeof(tcp_phdr_t));


				  	/* Fill the pseudoheader so we can compute the TCP checksum*/
					pseudohdr.src = ip->saddr;
					pseudohdr.dst = ip->daddr;
					pseudohdr.zero = 0;
					pseudohdr.protocol = ip->protocol;
					pseudohdr.tcplen = htons(nread-sizeof(*ip));
					/* Copy header and pseudoheader to a buffer to compute the checksum */  
					memcpy(tcpcsumblock, &pseudohdr, sizeof(tcp_phdr_t));   
					memcpy(tcpcsumblock+sizeof(tcp_phdr_t),(ip+1), tcpSize);

					//Calculate checksum
					tcp->check = in_cksum((unsigned short *)(tcpcsumblock), sizeof(tcp_phdr_t)+tcpSize); 
					fwPacket=1;
					
					//PORT RESOLUTION
                                        char * procName = searchTcpProcName (ntohs(tcp->dest));

                                        if (procName == NULL){
						procName="unknown";
					}

					if ((ntohs(tcp->source)==HTTP_PORT) || (ntohs(tcp->source)==HTTP_PORT_ALT)){
							/*TODO Parse HTTP: IS IT WORTH DOING IT IN RT?*/
							//USE https://github.com/joyent/http-parser
							/* 
							TODO: Get the 64 bytes of the HTTP response as in outgoing traffic or at least get the main ones
									NOTE: Even if it's HTTP, we are getting the TCP packets with the flags -> post-processing them!
							*/

						
							int dataoffset = tcp->doff;
							if (dataoffset%4!=0){
								dataoffset = dataoffset + (4-dataoffset%4);
							}
							int payload = nread -sizeof(*ip) - sizeof(*tcp) - dataoffset;
							if (payload >= MIN_HTTP_HEADER){
								/*Small packets can be just 'cos of TCP */
								//printf("* Obtaining INCOMING payload\n");
								if (payload > HTTP_HEADER_READ_SIZE){
									payload = HTTP_HEADER_READ_SIZE;
								}
								char tcpPayload[ payload ];
								int jumpTo = sizeof(*ip)+sizeof(*tcp)+dataoffset+4;
								//printf("* Bytes to ignore: %d\n", jumpTo);
								memset(tcpPayload, 0, sizeof(tcpPayload));
								memcpy(tcpPayload, &packet[jumpTo], payload-1);

								printf("\n\n--------------\n");
								printf("* PAYLOAD INCOMING HTTP (size %d):\n %s\n", sizeof(tcpPayload), tcpPayload);
								printf("-----------------\n\n");

								printf(log_buffer, "HTTP,%s,%d,%d,%s,%s,%d,%d,%d,%d,%d,%d, %d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n***%s\n***\n",procName,direction, fwPacket, sAddrBuf, dAddrBuf,ip->protocol,ntohs(ip->tot_len), ntohs(tcp->source), ntohs(tcp->dest), ntohs(tcp->seq),tcpSize, tcp->window, tcp->res1, tcp->doff, tcp->fin, tcp->syn, tcp->rst, tcp->psh, tcp->ack, tcp->urg, tcp->ece, tcp->cwr, tcpPayload);
                                                               // printf("Send: %s\n", log_buffer);

								print_log(log_buffer, sizeof(log_buffer));

							}
							else{//Do not print 64 bytes from tcp payload
								sprintf(log_buffer, "HTTP,%s,%d,%d,%s,%s,%d,%d,%d, %d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",procName,direction, fwPacket, sAddrBuf, dAddrBuf,ip->protocol,ntohs(ip->tot_len), ntohs(tcp->source), ntohs(tcp->dest), ntohs(tcp->seq),tcpSize, tcp->window, tcp->res1, tcp->doff, tcp->fin, tcp->syn, tcp->rst, tcp->psh, tcp->ack, tcp->urg, tcp->ece, tcp->cwr);
								print_log(log_buffer, sizeof(log_buffer));
							}


					}
					else{
						memset(log_buffer, 0, sizeof(log_buffer));
						sprintf(log_buffer, "TCP,%s,%d,%d,%s,%s,%d,%d,%d,%d,%d, %d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",procName,direction, fwPacket, sAddrBuf, dAddrBuf,ip->protocol,ntohs(ip->tot_len), ntohs(tcp->source), ntohs(tcp->dest), ntohs(tcp->seq),tcpSize, tcp->window, tcp->res1, tcp->doff, tcp->fin, tcp->syn, tcp->rst, tcp->psh, tcp->ack, tcp->urg, tcp->ece, tcp->cwr);
						print_log(log_buffer, sizeof(log_buffer));
					}


					break;
				case 17: 
					do_debug("INCOMING PROTOCOL: UDP\n");
					struct udphdr *udp = (struct udphdr *) (ip+1);
					udp->check=0;
					fwPacket=1;

					//Plot UDP
					if (ntohs(udp->source) == DNS_PORT){
/*
TODO
						int payload = nread -sizeof(*ip) - UDP_HDR_LENGTH;

						char udpPayload[ payload ];
						int jumpTo = sizeof(*ip)+UDP_HDR_LENGTH+1;
						memset(udpPayload, 0, sizeof(udpPayload));
						memcpy(udpPayload, &packet[jumpTo], payload-1);


								printf("\n\n--------------\n");
								printf("* PAYLOAD DNS (size %d):\n %s\n", sizeof(udpPayload), udpPayload);
								printf("-----------------\n\n");
*/

						memset(log_buffer, 0, sizeof(log_buffer));
						sprintf(log_buffer, "DNSRESOLUTION,%d,%d,%s,%s,%d,%d,%d,%d,%d\n",direction, fwPacket, sAddrBuf, dAddrBuf, ip->protocol, ntohs(ip->tot_len), ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len));
						print_log(log_buffer, sizeof(log_buffer));	
					}
					else{
						memset(log_buffer, 0, sizeof(log_buffer));
						sprintf(log_buffer, "UDP,%d,%d,%s,%s,%d,%d,%d,%d,%d\n",direction, fwPacket, sAddrBuf, dAddrBuf, ip->protocol, ntohs(ip->tot_len), ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len));
						print_log(log_buffer, sizeof(log_buffer));					
					}

					break;
				default: do_debug("PROTOCOL: UNKNOWN (Not supported yet)");
					memset(log_buffer, 0, sizeof(log_buffer));
					sprintf(log_buffer, "UNKNOWN,%d,%d,%s,%s,%d,%d\n",direction, fwPacket, sAddrBuf, dAddrBuf,ip->protocol,ntohs(ip->tot_len));
					print_log(log_buffer, sizeof(log_buffer));
					break;		
			}		

			//Set to 0 before re-calculating
			ip->check = 0; 
			ip->check=cksum(ip, 4*ip->ihl);
			do_debug("READOUT %lu: Read %d bytes from the tap interface\n",  nread);
			//Write on the FD
			if (fwPacket!=0){
				nwrite = cwrite(tap_fd, packet, nread);
		    do_debug("WRITEOUT %lu: Read %d bytes from the tap interface\n", nread);
			}
		}
	}
	while (1);
	//release mutex
	pthread_mutex_destroy(&mutex);
}

