/* * udptunnel
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

#include <utun/socket.h>
#include <utun/tun.h>
#include <utun/util.h>
#include <utun/tunnel_packet.h>

#define PASSPHRASE v[2]
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
	struct sockaddr_in client_addr, from,next_addr;
	socklen_t fromlen;
	fd_set rfds;
	struct tunnel_packet *tp;
	char buf[MTU];
	struct ip_header *ip;
	struct udp_header *udp;
	unsigned int buflen;
	unsigned short local_port;
	unsigned int version = 1;
	unsigned int temp;
	int ret;
	int tun_fd;
	int client_fd;
	int has_client = 0;
	unsigned int pass_len;

	tp = (struct tunnel_packet *)buf;
	memset(&next_addr, 0, sizeof(next_addr));
	next_addr.sin_family = AF_INET;
	next_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	next_addr.sin_port = htonl(12345);

	if(c < 3) {
		printf( "UDP Tunnel\n"
			"%s <port> <passphrase>\n", v[0]);
		return 0;
	}

	if(strtoport(v[1], &local_port) == 0) {
		printf("%s: Invalid port\n", v[0]);
		return 1;
	}
	
	pass_len = strlen(PASSPHRASE);
	tun_fd = tun_create();
	client_fd = socket_create(local_port);
	fromlen = sizeof(from);

/*#ifdef __linux__
        exec_script("linux_server.sh", v[1]);
#else
        exec_script("osx_server.sh", v[1]);
#endif*/
	
	FD_ZERO(&rfds);
	while(1) {
		FD_SET(client_fd, &rfds);
		FD_SET(tun_fd, &rfds);
		ret = select(client_fd+1, &rfds, NULL, NULL, NULL);

		if(ret == -1)
			break;
		if(FD_ISSET(tun_fd,&rfds)){
			printf("step3\n");
			buflen =tun_get_packet(tun_fd,tp->data, sizeof(buf)-sizeof(struct tunnel_packet));
			printf("step4\n");
			tp->type = TRAFFIC_PACKET;
			printf("step5\n");
			tp->cmd = 0;
			printf("has-client :%d\n",has_client);
			if(has_client){
				socket_put_packet(client_fd,&client_addr, sizeof(client_addr),buf, buflen+sizeof(struct tunnel_packet));
                                ip = (struct ip_header *)tp->data;
                                udp = (struct udp_header *)ip->data;
                                printf("size%d\n",buflen);
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

		if(FD_ISSET(client_fd, &rfds)) {
			buflen = socket_get_packet(client_fd, &from, &fromlen, buf, sizeof(buf));
			printf("raw data length:%d\n",buflen);
			if(tp->type == TRAFFIC_PACKET) {
				printf("normal packet recieved\n");
				if(client_addr.sin_addr.s_addr == from.sin_addr.s_addr && client_addr.sin_port == from.sin_port)
					printf("address is corrent");
					if(version != tp->version){
						printf("version mismatch");
						return;
					}
					if(tp->current_hop == tp->total_hops)
						printf("recieved packet");
					else{
						temp = tp->current_hop;
						next_addr.sin_addr.s_addr = htonl(INADDR_ANY);
						tp->current_hop = ++temp;
						next_addr.sin_addr.s_addr = tp->ip_address[temp];
						printf("forwarding packet to next_hop:%s\n",inet_ntoa(next_addr.sin_addr));
						socket_put_packet(client_fd,&next_addr,sizeof(next_addr),buf, buflen);

					}
					ip = (struct ip_header *)tp->data;
					udp = (struct udp_header *)ip->data;
					printf("size%d\n",buflen);
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
					printf("packet length%d\n\n",buflen);

			} else if(tp->type == CONTROL_PACKET && tp->cmd == AUTH_CMD) {
				if(buflen-sizeof(struct tunnel_packet) == pass_len && strncmp(tp->data, PASSPHRASE, pass_len) == 0) {
					printf("it works\n");
					client_addr = from;
					tp->cmd = OK_CMD;
					has_client = 1;
				} else
					tp->cmd = ERROR_CMD;
				socket_put_packet(client_fd, &from, sizeof(from), buf,  sizeof(struct tunnel_packet));
			}
		}
	}
	return 1;
}
