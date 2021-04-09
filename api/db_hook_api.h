#ifndef _DB_HOOK_API_H
#define _DB_HOOK_API_H


#include <linux/kernel.h>
#include <linux/module.h>

typedef struct db_packet_info {
    __be16 sport;
    __be16 dport;
    __u8 protocol;
    __be32 saddr;
    __be32 daddr;
}db_packet_info;

typedef struct db_filter {
    __be16 source;
}db_filter;
// major device number
#define DB_MAJOR_NUMBER 200
// device name in 
#define DB_DEVICE_NAME "db_hook"
// The device path.
#define DB_DEVICE_PATH "/dev/" DB_DEVICE_NAME

#define DB_FILTER_LENGTH sizeof(struct db_filter)
#define DB_PACKET_INFO_LENGTH sizeof(struct db_packet_info)

// magic number / nr / size
#define DB_IOCTL_ADD    _IOW(DB_MAJOR_NUMBER, 0, struct db_filter *)
#define DB_IOCTL_DEL    _IOW(DB_MAJOR_NUMBER, 1, struct db_filter *)
extern struct db_packet_info db_p_info[100];
// api
int db_hook_open(void);
int db_get_packet(int fd, int num) ;
int db_hook_register_filter(int fd, char *ip_str);
void db_hook_close(int fd);


#endif