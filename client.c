/*
 * udptunnel
 * Copyright © 2013 Felipe Astroza A.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
* You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <utun/socket.h>
#include <utun/tun.h>
#include <utun/util.h>
#include <utun/tunnel_packet.h>

#define PASSPHRASE v[3]

struct ip_header{
	#ifdef WORKS_BIGENDIAN
	u_int8_t ip_version:4,/*version 4*/
	ip_header_length:4;/*IPxieyishoubuchangdu*/
	#else
	u_int8_t ip_header_length:4,
	ip_version:4;
	
	#endif
	u_int8_t ip_tos;
	u_int16_t ip_length;
	u_int16_t ip_id;
	u_int16_t ip_off;
	u_int8_t ip_ttl;
	u_int8_t ip_protocol;
	u_int16_t ip_checksum;
	struct in_addr ip_sourse_address;
	struct in_addr ip_destination_address;
	char data[];
};

struct udp_header{
	u_int16_t udp_sourse_port;
	u_int16_t udp_destination_port;
	u_int32_t udp_length;
	u_int32_t udp_checksum;
	char data[];
	
};


int main(int c, char **v)
{
	struct sockaddr_in server_addr, from; 
	socklen_t fromlen;
	fd_set rfds;
	struct tunnel_packet *tp;
	struct ip_header *ip;
	struct udp_header *udp;
	char buf[MTU];
	unsigned int buflen;
	
	int ret;
	int tun_fd;
	int server_fd;
	int ret1;
	
	tp = (struct tunnel_packet *)buf;

	if(c < 4) {
		fprintf(stderr, "TCP/UDP/ICMP Tunnel over UDP\n"
			"%s <hostname> <port> <passphrase>\n", v[0]);
		return 0;
	}

	struct hostent* host_info = gethostbyname(v[1]);
	if (host_info == NULL) {
		fprintf(stderr, "%s: Invalid hostname or IPv4 address\n", v[1]);
		return 1;
	}

	memset(&server_addr, 0, sizeof(server_addr));
	memset(&from, 0, sizeof(from));
	memcpy(&server_addr.sin_addr, host_info->h_addr, host_info->h_length);
	if(strtoport(v[2], &server_addr.sin_port) == 0) {
		fprintf(stderr, "%s: Invalid port\n", v[0]);
		return 1;
	}
	server_addr.sin_family = AF_INET;
	tun_fd = tun_create();
	server_fd = socket_create(htons(12345));

	/* Sending authentication */
	tp->type = CONTROL_PACKET;
	tp->cmd = AUTH_CMD;
	strcpy(tp->data, PASSPHRASE);
	socket_put_packet(server_fd, &server_addr, sizeof(server_addr), buf, sizeof(struct tunnel_packet) + strlen(PASSPHRASE));

	/* Waiting acknowledge */
	fromlen = sizeof(struct sockaddr_in);
	buflen = socket_get_packet(server_fd, &from, &fromlen, buf, sizeof(buf));
	if(tp->type == CONTROL_PACKET) {
		if(tp->cmd != OK_CMD) {
			puts("Password is incorret");
			return 1;
		}
	} else {
		puts("Unexpected packet was received.");
		return 1;
	}

/*#ifdef __linux__
	exec_script("linux_client.sh", v[1]);
#else
	exec_script("osx_client.sh", v[1]);
#endif*/
	puts("+ Auth is OK.\n+ UDP Tunnel is running.");
	FD_ZERO(&rfds);
	while(1) {
		FD_SET(server_fd, &rfds);
		FD_SET(tun_fd, &rfds);
		ret = select(server_fd+1, &rfds, NULL, NULL, NULL);

		if(ret == -1)
			break;

		if(FD_ISSET(tun_fd, &rfds)) {
			buflen = tun_get_packet(tun_fd, tp->data, sizeof(buf)-sizeof(struct tunnel_packet));
			ip = (struct ip_header *)tp->data;
			udp = (struct udp_header *)ip->data;
			printf("tun send packet");
			printf("raw size%d\n",buflen);
			printf("sourse address:%s\n",inet_ntoa(ip->ip_sourse_address));
			printf("destination address:%s\n",inet_ntoa(ip->ip_destination_address));
			switch(ip->ip_protocol){
				case 6:printf("the transport layer protocol is tcp\n");break;
				case 17:printf("the transport layer protocol is udp\n");break;
				case 1:printf("the transport layer protocol is icmp\n");break;
				case 2:printf("the transport layer protocol is igmp\n");break;
				default:break;

			}
			printf("sourse port :%d\n",ntohs(udp->udp_sourse_port));
			printf("des port :%d\n",ntohs(udp->udp_destination_port));
			tp->type = TRAFFIC_PACKET;
			tp->cmd = 0;
			tp->version = 1;
			tp->current_hop = 0;
			tp->total_hops = 1;
			tp->ip_address[0] = inet_addr("192.168.10.3");
			tp->ip_address[1] = inet_addr("192.168.10.4");
			socket_put_packet(server_fd, &server_addr, sizeof(server_addr), buf, buflen + sizeof(struct tunnel_packet));
			printf("packet length%ld\n\n\n",buflen+sizeof(struct tunnel_packet));
		}

		if(FD_ISSET(server_fd, &rfds)) {
			buflen = socket_get_packet(server_fd, &from, &fromlen, buf, sizeof(buf));
			if(server_addr.sin_addr.s_addr == from.sin_addr.s_addr && server_addr.sin_port == from.sin_port)
				tun_put_packet(tun_fd, tp->data, buflen-sizeof(struct tunnel_packet));
				printf("tun get packet\n");
				ip = (struct ip_header *)tp->data;
				udp = (struct udp_header *)ip->data;
				printf("raw size%d\n",buflen);
				printf("sourse address:%s\n",inet_ntoa(ip->ip_sourse_address));
				printf("destination address:%s\n",inet_ntoa(ip->ip_destination_address));
				switch(ip->ip_protocol){
					case 6:printf("the transport layer protocol is tcp\n");break;
					case 17:printf("the transport layer protocol is udp\n");break;
					case 1:printf("the transport layer protocol is icmp\n");break;
					case 2:printf("the transport layer protocol is igmp\n");break;
					default:break;

				}
				printf("sourse port :%d\n",ntohs(udp->udp_sourse_port));
				printf("des port :%d\n",ntohs(udp->udp_destination_port));
				printf("packet length%ld\n\n\n",buflen-sizeof(struct tunnel_packet));
		}
	}

	return 1;
}