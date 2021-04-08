#ifndef _DB_HOOK_API_H
#define _DB_HOOK_API_H

struct db_packet_info {
    __be16 sport;
    __be16 dport;
    __u8 protocol;
    __be32 saddr;
    __be32 daddr;
};
struct db_filter {
    __be16 source;
};

#define DB_FILTER_LENGTH sizeof(struct db_filter)

#endif