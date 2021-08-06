#include <asm/uaccess.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/vmalloc.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/tcp.h>

#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_nat_helper.h>

#define CHECKSUM_HW 1
#define PROC_MAX_SIZE PAGE_SIZE
#define TCP_PAYLOAD_ADD_LEN 8
#define MAGIC_PAYLOAD1 0xa1
#define MAGIC_PAYLOAD2 0xc1

static unsigned char tcp_payload_add[8] = {0xfd, TCP_PAYLOAD_ADD_LEN, MAGIC_PAYLOAD1, 0, MAGIC_PAYLOAD2, 0};

static const char *proc_name = "ioreuse";
static struct proc_dir_entry *proc_entry;
static char *proc_buff;
static unsigned long proc_buff_len;
static char dst_host[16];
static unsigned int dst_port;
static unsigned int trans_port;

int handle_proc_msg(char *msg, int len)
{
    int num;
    num = sscanf(msg, "%s %d %d", dst_host, &dst_port, &trans_port);
    if (num != 3) {
        printk(KERN_ERR "param number error\n");
        return -1;
    }
    tcp_payload_add[3] = (unsigned char)((trans_port & 0xff00) >> 8);
    tcp_payload_add[5] = (unsigned char)(trans_port & 0xff);
    printk(KERN_INFO "Tag packet to %s:%d, transfer to %s:%d\n", dst_host, dst_port, dst_host, trans_port);
    return 0;
}

static ssize_t proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
    if (*ppos > 0 || count > PROC_MAX_SIZE) {
        printk(KERN_ERR "proc_write msg too long\n");
        return -EFAULT;
    }
    if (copy_from_user(proc_buff, ubuf, count)) {
        printk(KERN_ERR "proc_write copy_from_user failed\n");
        return -EFAULT;
    }
    proc_buff_len = count;
    proc_buff[proc_buff_len] = 0;
    *ppos = count;
    if(handle_proc_msg(proc_buff, proc_buff_len)) {
        printk(KERN_ERR "proc data handle failed\n");
        return -EFAULT;
    }
    return count;
}

static ssize_t proc_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
    if(*ppos > 0 || count < PROC_MAX_SIZE)
        return 0;
    if(copy_to_user(ubuf, proc_buff, proc_buff_len)) {
        printk(KERN_ERR "proc_read copy_to_user failed\n");
        return -EFAULT;
    }
    *ppos = proc_buff_len;
    return proc_buff_len;
}

static struct file_operations proc_ops =
{
    .owner = THIS_MODULE,
    .read = proc_read,
    .write = proc_write,
};

static int proc_init(void)
{
    proc_buff_len = 0;
    proc_buff = NULL;
    proc_buff = (char *)vmalloc(PROC_MAX_SIZE);
    if (! proc_buff) {
        printk(KERN_ERR "proc_init vmalloc failed\n");
        return -1;
    }
    memset(proc_buff, 0, PROC_MAX_SIZE);
    proc_entry = proc_create(proc_name, 0644, NULL, &proc_ops);
    if (! proc_entry) {
        vfree(proc_buff);
        proc_buff = NULL;
        printk(KERN_ERR "proc_init create_proc_entry failed\n");
        return -1;
    }
    return 0;
}

static int proc_exit(void)
{
    proc_remove(proc_entry);
    vfree(proc_buff);
    proc_buff = NULL;
    return 0;
}

unsigned int func_out(
    const struct nf_hook_ops *ops,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    const struct nf_hook_state *state
)
{
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);
    char ip_addr[16];
    snprintf(ip_addr, 16, "%pI4", &iph->daddr);
    if(! strcmp(ip_addr, dst_host) && iph->protocol == IPPROTO_TCP && htons(tcph->dest) == dst_port)
    {
        if (tcph->syn == 1) {
            enum ip_conntrack_info ctinfo;
            struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
            //nfct_seqadj_ext_add(ct);
            if (ct) {
                __nf_nat_mangle_tcp_packet(skb,
                                           ct,
                                           ctinfo,
                                           iph->ihl * 4,
                                           0,
                                           0,
                                           tcp_payload_add,
                                           TCP_PAYLOAD_ADD_LEN, true);
            }
        }
    }
    return NF_ACCEPT;
}

static struct nf_hook_ops nfho_out = {
    .hook = func_out,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_MANGLE,
    .owner = THIS_MODULE,
};

static int __init net_init(void)
{
    // Default 127.0.0.1:80 -> 127.0.0.1:22, mode 1
    strcpy(dst_host, "127.0.0.1");
    dst_port = 80;
    trans_port = 22;
    if (proc_init()) {
        printk(KERN_ERR "proc_init() failed\n");
        return -1;
    }
    proc_buff_len = 15;
    snprintf(proc_buff, proc_buff_len, "%s %d %d", dst_host, dst_port, trans_port);
    if (nf_register_hook(&nfho_out)) {
        printk(KERN_ERR "nf_register_hook() failed\n");
        return -1;
    }
    return 0;
}

static void __exit net_exit(void)
{
    nf_unregister_hook(&nfho_out);
    proc_exit();
}

module_init(net_init);
module_exit(net_exit);
MODULE_AUTHOR("newfirebw@gmail.com");
MODULE_LICENSE("GPL");
