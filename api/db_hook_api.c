
#include <stdio.h>
#include <sys/types.h>
#include<arpa/inet.h>  // inet_ntop inet_pton
#include <sys/fcntl.h>   // O_RDWR
#include <unistd.h>    // read
#include <errno.h>     // errno
#include <string.h>    // strerror()
#include <sys/ioctl.h>  // ioctl();
#include <stdlib.h> 
#include "db_hook_api.h"
// int fd = -1;
struct db_packet_info db_p_info[100];

// int new_packet_info(int num)
// {
//     db_p_info = (struct db_packet_info *)malloc(num * DB_PACKET_INFO_LENGTH);
//     if (!db_p_info) {
//         printf("OOM!\n");
//     }
// }

// int del_packet_info(int num)
// {
//     free(db_p_info);
// }
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

int db_get_packet(int fd, int num) 
{   
    // struct db_packet_info p_info;
    // new_packet_info(num);
    int size = num * DB_PACKET_INFO_LENGTH;
    return read(fd, db_p_info, size);
}

void db_hook_close(int fd) 
{
    close(fd);
}