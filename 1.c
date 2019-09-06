#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>

int main(){
	struct sockaddr_in dest_info;
	char *data = "TCP message\n";

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

	printf("%d\n",sock);

	memset((char *) &dest_info, 0, sizeof(dest_info));
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr.s_addr = inet_addr("10.0.2.10");
	dest_info.sin_port = htons(9090);

	int bytes =	sendto(sock, data, strlen(data), 0, (struct sockaddr *) &dest_info, sizeof(dest_info));
	printf("bytes %d\n", bytes);
	close(sock);
	return 0;
}