#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/jiffies.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/tcp.h>

#define CHECKSUM_HW 1
#define SESSION_TIMEOUT 600
#define SESSION_MAX 256
#define MAGIC_PAYLOAD 0xf726

typedef struct host {
    char src_ip[16];
    char dst_ip[16];
    unsigned int src_port;
    unsigned int dst_port;
    unsigned int proto;
} t_conn;

typedef struct session {
    t_conn conn;
    unsigned long last_pkt_ts;
    unsigned int trans_port;
    unsigned int in_use;
} t_session;

static unsigned int preset_trans_mode[16] = {0, 12138, 21, 22, 3306, 6379, 27017};

// Max [SESSION_MAX] connections from client
static t_session session_table[SESSION_MAX];

int update_table(const t_conn *c, unsigned int trans_port)
{
    int i;
    int found = 0;
    for(i = 0; i < SESSION_MAX; i++) {
        if(session_table[i].in_use == 1) {
            if(jiffies_to_msecs(jiffies - session_table[i].last_pkt_ts) / 1000 > SESSION_TIMEOUT) {
                session_table[i].in_use = 0;
                continue;
            }
            if(! strcmp(session_table[i].conn.src_ip, c->src_ip) &&
            ! strcmp(session_table[i].conn.dst_ip, c->dst_ip) &&
            session_table[i].conn.src_port == c->src_port &&
            session_table[i].conn.dst_port == c->dst_port &&
            session_table[i].conn.proto == c->proto) {
                session_table[i].last_pkt_ts = jiffies;
                found = 1;
            }
        }
    }
    if(! found) {
        for(i = 0; i < SESSION_MAX; i++) {
            if(session_table[i].in_use == 0) {
                session_table[i].last_pkt_ts = jiffies;
                strcpy(session_table[i].conn.src_ip, c->src_ip);
                strcpy(session_table[i].conn.dst_ip, c->dst_ip);
                session_table[i].conn.src_port = c->src_port;
                session_table[i].conn.dst_port = c->dst_port;
                session_table[i].conn.proto = c->proto;
                session_table[i].trans_port = trans_port;
                session_table[i].in_use = 1;
                break;
            }
        }
    }
    return 0;
}

t_conn *find_table(const t_conn *c)
{
    int i;
    for(i = 0; i < SESSION_MAX; i++) {
        if(session_table[i].in_use == 1) {
            if(! strcmp(session_table[i].conn.src_ip, c->dst_ip) &&
               session_table[i].conn.src_port == c->dst_port &&
               session_table[i].conn.proto == c->proto) {
                return &session_table[i].conn;
            }
        }
    }
    return NULL;
}

unsigned int func_in(
    const struct nf_hook_ops *ops,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    const struct nf_hook_state *state
)
{
    unsigned int trans_port;
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);
    t_conn tc;
    char ip_addr[16];
    if(iph->version == 4 && iph->protocol == IPPROTO_TCP && tcph->res1 != 0)
    {
        if(tcph->res1 < 0 || tcph->res1 > 15) {
            return -EFAULT;
        }
        snprintf(ip_addr, 16, "%pI4", &iph->saddr);
        strcpy(tc.src_ip, ip_addr);
        snprintf(ip_addr, 16, "%pI4", &iph->daddr);
        strcpy(tc.dst_ip, ip_addr);
        tc.src_port = ntohs(tcph->source);
        tc.dst_port = ntohs(tcph->dest);
        tc.proto = IPPROTO_TCP;
        trans_port = preset_trans_mode[tcph->res1];
        tcph->res1 = 0;
        update_table(&tc, trans_port);
        tcph->dest = ntohs(trans_port);
        iph->check = 0;
        iph->check = ip_fast_csum((unsigned char*)iph, iph->ihl);
        if(skb->ip_summed == CHECKSUM_HW)
        {
            tcph->check = csum_tcpudp_magic(iph->saddr,iph->daddr,(ntohs(iph ->tot_len)-iph->ihl*4), IPPROTO_TCP,csum_partial(tcph,(ntohs(iph ->tot_len)-iph->ihl*4),0));
            skb->csum = offsetof(struct tcphdr, check);
        }
    }
    return NF_ACCEPT;
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
    t_conn tc;
    t_conn *real_tc;
    if(iph->version == 4 && iph->protocol == IPPROTO_TCP)
    {
        snprintf(ip_addr, 16, "%pI4", &iph->saddr);
        strcpy(tc.src_ip, ip_addr);
        snprintf(ip_addr, 16, "%pI4", &iph->daddr);
        strcpy(tc.dst_ip, ip_addr);
        tc.src_port = ntohs(tcph->source);
        tc.dst_port = ntohs(tcph->dest);
        tc.proto = IPPROTO_TCP;
        real_tc = find_table(&tc);
        if(real_tc) {
            tcph->source = ntohs(real_tc->dst_port);
            iph->check = 0;
            iph->check = ip_fast_csum((unsigned char*)iph, iph->ihl);
            if(skb->ip_summed == CHECKSUM_HW)
            {
                tcph->check = csum_tcpudp_magic(iph->saddr,iph->daddr,(ntohs(iph ->tot_len)-iph->ihl*4), IPPROTO_TCP,csum_partial(tcph,(ntohs(iph ->tot_len)-iph->ihl*4),0));
                skb->csum = offsetof(struct tcphdr, check);
            }
        }
    }
    return NF_ACCEPT;
}

static struct nf_hook_ops nfho_in = {
    .hook = func_in,
    .pf = PF_INET,
    .hooknum =NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_LAST,
    .owner = THIS_MODULE,
};

static struct nf_hook_ops nfho_out = {
    .hook = func_out,
    .pf = PF_INET,
    .hooknum =NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST,
    .owner = THIS_MODULE,
};

static int __init net_init(void)
{
    memset(session_table, 0, SESSION_MAX * sizeof(t_session));
    if (nf_register_hook(&nfho_in) || nf_register_hook(&nfho_out)) {
        printk(KERN_ERR"nf_register_hook() failed\n");
        return -1;
    }
    return 0;
}

static void __exit net_exit(void)
{
    nf_unregister_hook(&nfho_in);
    nf_unregister_hook(&nfho_out);
}

module_init(net_init);
module_exit(net_exit);
MODULE_AUTHOR("newfirebw@gmail.com");
MODULE_LICENSE("GPL");
