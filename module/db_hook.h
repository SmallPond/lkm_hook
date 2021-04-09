#ifndef _DB_HOOK_H_
#define __DB_HOOK_H_


#include <linux/kernel.h>
#include <linux/module.h>
// major device number
#define DB_MAJOR_NUMBER 200

// device name in 
#define DB_DEVICE_NAME "db_hook"

// The device path.
#define DB_DEVICE_PATH "/dev/" DB_DEVICE_NAME

// The device class -- this is a character device driver.
#define DB_CLASS_NAME  "db_hook"

/* IOctl CMD */
// magic number / nr / size
#define DB_IOCTL_ADD    _IOW(DB_MAJOR_NUMBER, 0, struct db_filter *)
#define DB_IOCTL_DEL    _IOW(DB_MAJOR_NUMBER, 1, struct db_filter *)
/* IOctl CMD */

#define DB_MAX_PACKET_BUFFER_NUM  2048
#define DB_KFIFO_BUFFER_SIZE      (DB_MAX_PACKET_BUFFER_NUM*sizeof(struct db_packet_info*))
struct db_packet_info {
    __be16 sport;
    __be16 dport;
    __u8 protocol;
    __be32 saddr;
    __be32 daddr;
};
struct db_filter {
    __be32 source;
};

#define DB_FILTER_LENGTH sizeof(struct db_filter)
#define DB_PACKET_INFO_LENGTH sizeof(struct db_packet_info )
#define db_filter_is_same(n1, n2) ((n1)->source == (n2)->source)





#endif 