
#include <stdio.h>
#include <sys/types.h>
#include<arpa/inet.h>  // inet_ntop inet_pton
#include <sys/fcntl.h>   // O_RDWR
#include <unistd.h>    // read
#include <errno.h>     // errno
#include <string.h>    // strerror()
#include <sys/ioctl.h>  // ioctl();

#include "db_hook_api.h"
// int fd = -1;

int db_hook_open(void)                 
{
    int fd = -1;
    fd = open(DB_DEVICE_PATH, O_RDWR);
    if (fd < 0)
    {
        // printf("Failed to open the device...");
        return -1;
    }
    // printf("Connection established between the application and the device\n");
    return fd;

}

int db_hook_register_filter(int fd, char *ip_str)
{
    struct db_filter filter;
    int ret;
    inet_pton(AF_INET, ip_str, &(filter.source));
    // inet_ntop(AF_INET, (void *)&(filter.source), (char *)&saddr[0], 16);
    // printf("source b %u, str %s\n", filter.source, saddr);

    ret = ioctl(fd, DB_IOCTL_ADD, &filter);

    return ret;

}

int db_get_packet(int fd, struct db_packet_info* p_info) 
{   
    // struct db_packet_info p_info;
    return read(fd, p_info, DB_PACKET_INFO_LENGTH);
}

void db_hook_close(int fd) 
{
    close(fd);
}