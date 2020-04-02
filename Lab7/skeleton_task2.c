#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>

// struct used to register our function
static struct nf_hook_ops nfho;

// hook function itself
unsigned int hook_func(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state) {
  struct iphdr *iph;
  struct tcphdr *tcph;

  iph = ip_hdr(skb);
  tcph = (void *)iph + iph->ihl * 4;

  // Rule 1: Preventing VM A from doing telnet to VM B
  if (iph->protocol == IPPROTO_TCP && iph->saddr == inet_addr("10.0.2.7") &&
      iph->daddr == inet_addr("10.0.2.8")) {
    if (ntohs(tcph->dest) == 23) {
      return NF_DROP;
    }
  }
  // Rule 2: Preventing VM A from visiting a website
  // Rule 3: Preventing VM A from doing SSH to VM B

  return NF_DROP;
}

// initialise routine
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

// remove routine
void removeFilter(void) {
  printk(KERN_INFO "Telnet filter is being removed.\n");
  nf_unregister_hook(&nfho);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
