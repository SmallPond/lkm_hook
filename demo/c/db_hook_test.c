#include<stdio.h>
#include<sys/types.h>
#include<arpa/inet.h>  // inet_ntop inet_pton
#include<sys/fcntl.h>
#include<unistd.h>
#include <errno.h>     // errno
#include <string.h>    // strerror()
#include <sys/ioctl.h>  // ioctl();
#include "db_hook.h"


// 159.75.7.136
int main(int argc, char** argv)
{
    (void) argc;
    (void) argv;
    
    int i, ret, fd, length;
    struct db_packet_info p_info;
    struct db_filter filter;
    char saddr[16];
    char daddr[16];
    printf("Open the connection between the the application and the device...\n");
    fd = open("/dev/db_hook", O_RDWR);

    if (fd < 0)
    {
        perror("Failed to open the device...");
        return errno;
    }
    printf("Connection established between the application and the device\n");
  
    inet_pton(AF_INET, "159.75.7.136", &(filter.source));
    inet_ntop(AF_INET, (void *)&(filter.source), (char *)&saddr[0], 16);
    printf("source b %u, str %s\n", filter.source, saddr);
    /* add the filter */
    ret = ioctl(fd, DB_IOCTL_ADD, &filter);
    printf("Result: %d-%d %s\n", ret, errno, strerror(errno));

    while (!read(fd, &p_info, DB_PACKET_INFO_LENGTH));
    printf("recv a packet from ip-port:%u,%u to %u,%u\n",p_info.saddr, p_info.sport, p_info.daddr, p_info.dport);
    // uint32_t saddr_n = htonl(p_info.saddr);
    // uint32_t daddr_n = htonl(p_info.daddr);
    inet_ntop(AF_INET, (void *)&(p_info.saddr), (char *)&saddr[0], 16);
    inet_ntop(AF_INET, (void *)&(p_info.daddr), (char *)&daddr[0], 16);
    printf("recv a packet from ip-port:%s,%d to %s,%d\n",saddr, p_info.sport, daddr, p_info.dport);
    sleep(1);
    close(fd);

    return 0;
}
