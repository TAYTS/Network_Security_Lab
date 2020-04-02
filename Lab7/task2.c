#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/string.h>

static struct nf_hook_ops nfho;

unsigned int hook_func(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state) {
  struct iphdr *iph;
  struct tcphdr *tcph;
  char srcAddr[16];
  char dstAddr[16];
  char hostA_Addr[16] = "10.0.2.7";
  char hostB_Addr[16] = "10.0.2.8";
  char facebook_Addr[16] = "157.240.13.35";

  iph = ip_hdr(skb);
  tcph = (void *)iph + iph->ihl * 4;

  snprintf(srcAddr, 16, "%pI4", &iph->saddr);
  snprintf(dstAddr, 16, "%pI4", &iph->daddr);
  
  // Rule 1: Preventing VM A from doing telnet to VM B
  if (iph->protocol == IPPROTO_TCP && strcmp(srcAddr, hostA_Addr) == 0 && strcmp(dstAddr, hostB_Addr) == 0 && tcph->dest == htons(23)) {
    return NF_DROP;
  }
 
 // Rule 2: Preventing VM A from visiting a website
 if (iph->protocol == IPPROTO_TCP && strcmp(srcAddr, hostA_Addr) == 0 && strcmp(dstAddr, facebook_Addr) == 0 && tcph->dest == htons(443)) {
    return NF_DROP;
  }

 // Rule 3: Preventing VM A from doing SSH to VM B

  return NF_ACCEPT;
}

int setUpFilter(void) {
  printk(KERN_INFO "Registering a Telnet filter.\n");
  nfho.hook = hook_func;
  nfho.hooknum = NF_INET_POST_ROUTING;
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FIRST;

  // Register the hook.
  nf_register_hook(&nfho);
  return 0;
}

void removeFilter(void) {
  printk(KERN_INFO "Telnet filter is being removed.\n");
  nf_unregister_hook(&nfho);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
