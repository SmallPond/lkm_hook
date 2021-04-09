#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/tcp.h>   // tcp_hdr()
#include <linux/ip.h>    // ip_hdr()
#include <linux/inet.h>  // in_aton()
#include <linux/fs.h>   // register_chrdev
#include <linux/version.h> // LINUX_KERNEL_VERSION
#include <linux/kfifo.h>   // ring buffer

#include "db_hook.h"
/*
struct nf_hook_ops {
	// User fills in from here down. 
	nf_hookfn		*hook;
	struct net_device	*dev;
	void			*priv;
	u_int8_t		pf;  // protocol flags
	unsigned int		hooknum; // 存放的是用户自定义的钩子函数的调用时机
	// Hooks are ordered in ascending priority. 
	int			priority;
};

*/

struct db_list_s
{
  struct db_filter filter;     /*!< The FILTER. */
  struct list_head list;       /*!< The list. */
};

// hook device 
struct db_hook_dev {
    bool opened;
    struct class*    db_device_class; 
    struct device*   db_device; 
    struct list_head db_filters; 
    unsigned int     db_filter_num;
};
struct db_hook_dev db_hook_dev;

DECLARE_KFIFO(db_kfifo, struct db_packet_info*, DB_KFIFO_BUFFER_SIZE);

struct nf_hook_ops in_hook;  
struct nf_hook_ops out_hook;

#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4, 4, 0))
  static unsigned int watch_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4, 1, 0))
  static unsigned int watch_in(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct nf_hook_state *state)
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(3, 12, 0))
  static unsigned int watch_in(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *_in, const struct net_device *_out, int (*okfn)(struct sk_buff *))
#else
  static unsigned int watch_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *_in, const struct net_device *_out, int (*okfn)(struct sk_buff *))
#endif
{
    struct tcphdr *tcp;
    struct iphdr *ip;
    struct list_head *ptr, *next;
    struct db_list_s *tmp;
    struct db_packet_info *new ;
    // __be32 saddr_aton;
    tcp = tcp_hdr(skb);
    ip = ip_hdr(skb);

    list_for_each_safe(ptr, next, &db_hook_dev.db_filters)
    {
        tmp = list_entry(ptr, struct db_list_s, list);
        // saddr_aton = in_aton(tmp->filter->source);
        if(ip->saddr == tmp->filter.source) {
            // add to ring buffer
            new = (struct db_packet_info *)kmalloc(sizeof(struct db_packet_info), GFP_KERNEL);
            new->sport = tcp->source;
            new->dport = tcp->dest;
            new->saddr = ip->saddr;
            new->daddr = ip->daddr;
            new->protocol = ip->protocol;
            if(!kfifo_put(&db_kfifo, new)) {
                kfree(new);
            }
            printk("source: %u:%u to dest:%u:%u\n", ip->saddr, tcp->source, ip->daddr, tcp->dest);
            break;
        }
    }
    // Continue traversal as normal.
    return NF_ACCEPT;
}
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4, 4, 0))
  static unsigned int watch_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4, 1, 0))
  static unsigned int watch_out(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct nf_hook_state *state)
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(3, 12, 0))
  static unsigned int watch_out(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *_in, const struct net_device *_out, int (*okfn)(struct sk_buff *))
#else
  static unsigned int watch_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *_in, const struct net_device *_out, int (*okfn)(struct sk_buff *))
#endif
{
    struct tcphdr *tcp;
    struct iphdr *ip;
    struct list_head *ptr, *next;
    struct db_list_s *tmp;
    struct db_packet_info *new ;
    
    // __be32 saddr_aton;
    tcp = tcp_hdr(skb);
    ip = ip_hdr(skb);

    // printk("source: %u\n", ip->saddr);
    list_for_each_safe(ptr, next, &db_hook_dev.db_filters)
    {
        tmp = list_entry(ptr, struct db_list_s, list);
        // saddr_aton = in_aton(tmp->filter->source);
        if(ip->saddr == tmp->filter.source) {
            // add to ring buffer
            new = (struct db_packet_info *)kmalloc(sizeof(struct db_packet_info), GFP_KERNEL);
            new->sport = tcp->source;
            new->dport = tcp->dest;
            new->saddr = ip->saddr;
            new->daddr = ip->daddr;
            new->protocol = ip->protocol;
            if(!kfifo_put(&db_kfifo, new)) {
                kfree(new);
                // break;
            }
            printk("[DB] [watch_out]source: %u:%u to dest:%u:%u\n", ip->saddr, tcp->source, ip->daddr, tcp->dest);
        }
    }
    return NF_ACCEPT;

}

static void db_filter_list_clear(void)
{
  struct list_head *ptr, *next;
  struct db_list_s *tmp;
  list_for_each_safe(ptr, next, &db_hook_dev.db_filters)
  {
    tmp = list_entry(ptr, struct db_list_s, list);
    list_del(ptr);
    kfree(tmp);
  }
  db_hook_dev.db_filter_num = 0;
}

static void db_packet_info_clear(void)
{
    struct db_packet_info* pack_info;
    while (kfifo_get(&db_kfifo, &pack_info)) {
        kfree(pack_info);
    }
}

static int db_dev_open(struct inode *inodep, struct file *filep)
{
    if(db_hook_dev.opened) {
        printk(KERN_ALERT "[DB] Device already opened.\n");
        return -EBUSY;
    }
    printk(KERN_INFO "db_dev_open\n");
    db_hook_dev.opened = true;
    return 0;
}

static ssize_t db_dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset)
{
    int error_count = 0;
    int num = len/DB_PACKET_INFO_LENGTH;
    int packet_count = 0;
    struct db_packet_info* p_info;
    // printk(KERN_INFO "[DB] db_dev_read  KFIFO LEN: %u\n",kfifo_len(&db_kfifo));
    while(num--) {
        if(kfifo_get(&db_kfifo, &p_info)) {
            // printk("source: %u:%u to dest:%u:%u\n", p_info->saddr, p_info->sport, p_info->daddr, p_info->dport);
            error_count = copy_to_user(buffer, p_info, DB_PACKET_INFO_LENGTH);
            if (error_count) {
                printk(KERN_ALERT "[DB] The copy to user failed: %d\n", error_count);
                return -EFAULT;
            }
            packet_count++;
            buffer += DB_PACKET_INFO_LENGTH;
        } else {
            return packet_count;
        }
    }
    return packet_count;

}

static int db_dev_release(struct inode *inodep, struct file *filep)
{
  db_filter_list_clear();
  db_packet_info_clear();
  db_hook_dev.opened = false;
  return 0;
}
#if (LINUX_KERNEL_VERSION < KERNEL_VERSION(2,6,35))
  static int db_dev_ioctl(struct inode *i, struct file *file, unsigned int cmd, unsigned long arg)
#else
static long db_dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
#endif
{
    int err = 0;
    struct list_head *ptr, *next;
    struct db_filter filter;
    struct db_list_s *new, *tmp;
    char* user_buffer = (char*)arg;
    printk(KERN_INFO "[DB] db_dev_ioctl cmd:%d.\n", cmd);
    switch(cmd) {
        case DB_IOCTL_ADD:
        {
            printk(KERN_INFO "[DB] db_dev_ioctl case DB_IOCTL_ADD.\n");
            if(copy_from_user(&filter, user_buffer, DB_FILTER_LENGTH))
            {
              printk(KERN_INFO "[DB] The copy from user failed\n");
              err = -EIO;
            }
            else
            {
                new = kmalloc(sizeof(struct db_list_s), GFP_KERNEL);
                if(!new)
                {
                    printk(KERN_INFO "[DB] not enough memory.\n");
                    err = -ENOMEM;
                }
                else
                {
                    /* add new FILTER */
                    memcpy(&new->filter, &filter, DB_FILTER_LENGTH);
                    memset(&new->list, 0, sizeof(struct list_head));
                    db_hook_dev.db_filter_num++;
                    list_add_tail(&new->list, &db_hook_dev.db_filters);
                }
            }
            break;
        }
        case DB_IOCTL_DEL:
        {
            if(copy_from_user(&filter, user_buffer, DB_FILTER_LENGTH))
            {
                printk(KERN_ALERT "[DB] The copy from user failed\n");
                err = -EIO;
            }
            else
            {
                list_for_each_safe(ptr, next, &db_hook_dev.db_filters)
                {
                    tmp = list_entry(ptr, struct db_list_s, list);
                    if(db_filter_is_same(&filter, &tmp->filter))
                    {
                        db_hook_dev.db_filter_num--;
                        list_del(ptr);
                        kfree(tmp);
                        break;
                    }
                }
            }
            break;
        }  
        default:
            err = -ENOTTY;
       
    }
    return err;
}
static struct file_operations fops =
{
  .open = db_dev_open,
  .read = db_dev_read,
#if (LINUX_KERNEL_VERSION < KERNEL_VERSION(2,6,35))
 .ioctl = db_dev_ioctl,
#else
  .unlocked_ioctl = db_dev_ioctl,
#endif
  .release = db_dev_release,
};


void db_hook_start(void) {
    // hook func
    in_hook.hook = watch_in;
    in_hook.pf = NFPROTO_IPV4;
    // in_hook.hooknum = NF_INET_PRE_ROUTING;
    in_hook.hooknum = NF_INET_LOCAL_IN;
    in_hook.priority = NF_IP_PRI_FIRST;
    printk("packet-hook start\n");
    out_hook.hook = watch_out;
    out_hook.pf = NFPROTO_IPV4;
    out_hook.hooknum = NF_INET_LOCAL_OUT;
    out_hook.priority = NF_IP_PRI_FIRST;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,12,14)
    nf_register_hook(&in_hook);
    nf_register_hook(&out_hook);
#else
    nf_register_net_hook(&init_net, &in_hook); 
    nf_register_net_hook(&init_net, &out_hook); 
#endif
}

static int __init db_hook_init(void)
{

    int major_number;
    // struct net_device *dev;
    printk(KERN_INFO "[DB] Initializing the DB LKM.\n");

    /* Try to dynamically allocate a major number for the device -- more difficult but worth it */
    major_number = register_chrdev(DB_MAJOR_NUMBER, DB_DEVICE_NAME, &fops);
    if (major_number < 0)
    {
        printk(KERN_ALERT "DB failed to register a major number.\n");
        return major_number;
    }
    printk(KERN_INFO "[DB] registered correctly with major number %d\n", DB_MAJOR_NUMBER);

    /* Register the device class */
    db_hook_dev.db_device_class = class_create(THIS_MODULE, DB_CLASS_NAME);
    if (IS_ERR(db_hook_dev.db_device_class))
    {
        unregister_chrdev(DB_MAJOR_NUMBER, DB_DEVICE_NAME);
        printk(KERN_ALERT "[DB] Failed to register device class.\n");
        return PTR_ERR(db_hook_dev.db_device_class);
    }
    printk(KERN_INFO "[DB] device class registered correctly.\n");

    /* Register the device driver */
    db_hook_dev.db_device = device_create(db_hook_dev.db_device_class, NULL, MKDEV(DB_MAJOR_NUMBER, 0), NULL, DB_DEVICE_NAME);
    /* Clean up if there is an error */
    if (IS_ERR(db_hook_dev.db_device))
    {
        class_destroy(db_hook_dev.db_device_class);
        unregister_chrdev(DB_MAJOR_NUMBER, DB_DEVICE_NAME);
        printk(KERN_ALERT "[DB] Failed to create the device.\n");
        return PTR_ERR(db_hook_dev.db_device);
    }
    /* device was initialized */
    printk(KERN_INFO "[DB] device class created correctly.\n");
    db_hook_dev.db_filter_num = 0;
    INIT_LIST_HEAD(&db_hook_dev.db_filters);

    db_hook_dev.opened = false;
    INIT_KFIFO(db_kfifo);
    printk(KERN_INFO "[DB] KFIFO LEN: %u",kfifo_len(&db_kfifo));
    db_hook_start();
    return 0;
}

static void __exit db_hook_exit(void)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,12,14)
    nf_unregister_hook(&in_hook);
    nf_unregister_hook(&out_hook);
#else
    nf_unregister_net_hook(&init_net, &in_hook); 
    nf_unregister_net_hook(&init_net, &out_hook); 
#endif
    db_filter_list_clear();
    db_packet_info_clear();
    /* remove the device */
    device_destroy(db_hook_dev.db_device_class, MKDEV(DB_MAJOR_NUMBER, 0));
    /* unregister the device class */
    class_unregister(db_hook_dev.db_device_class);
    /* remove the device class */
    class_destroy(db_hook_dev.db_device_class);
    /* unregister the major number */
    unregister_chrdev(DB_MAJOR_NUMBER, DB_DEVICE_NAME);
    printk("packet-HOOK stop\n");

}

module_init(db_hook_init);
module_exit(db_hook_exit);

MODULE_LICENSE("GPL");