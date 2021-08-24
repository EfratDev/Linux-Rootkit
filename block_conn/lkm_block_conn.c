#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/net.h>
#include <net/sock.h>

#define BLOCK_IP "127.0.0.1"

MODULE_LICENSE("GPL");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef int (*inet_accept_t)(struct socket *sock, struct socket *newsock, int flags, bool kern);

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

extern unsigned long __force_order;
static inline void mywrite_cr0(unsigned long value) {
  asm volatile("mov %0,%%cr0":"+r"(value),"+m"(__force_order));
}

struct proto_ops * inet_stream_ops;
inet_accept_t inet_accept_org;
  
static kallsyms_lookup_name_t get_lookup(void) {
  kallsyms_lookup_name_t kallsyms_lookup_name;

  /* register the kprobe */
  register_kprobe(&kp);

  /* assign kallsyms_lookup_name symbol to kp.addr */
  kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    
  /* done with the kprobe, so unregister it */
  unregister_kprobe(&kp);
  return kallsyms_lookup_name;
}

int block_conn_inet_accept(struct socket *sock, struct socket *newsock, int flags, bool kern) {
  int fd;
  printk(KERN_ALERT "client address: %lu", (unsigned long) &newsock->sk->__sk_common.skc_daddr);
  fd = inet_accept_org(sock, newsock, flags, kern);
  /*
  if (memcmp(client_addr, BLOCK_IP) == 0) {
    return -EINVAL;
  }
  */
  return fd
}

static int __init hello_init(void) {
  unsigned long orig_cr0;
  kallsyms_lookup_name_t kallsyms_lookup_name;
  
  kallsyms_lookup_name = get_lookup();  
  inet_stream_ops = (struct proto_ops *) kallsyms_lookup_name("inet_stream_ops");
  if (inet_stream_ops == 0) {
    printk(KERN_ALERT "could not get inet_stream_ops address");
    return 0;
  }
  orig_cr0 = read_cr0();
  mywrite_cr0(orig_cr0 & (~0x10000));
  inet_accept_org = inet_stream_ops->accept;
  inet_stream_ops->accept = &block_conn_inet_accept;
  mywrite_cr0(orig_cr0);
  printk(KERN_ALERT "%lu", (unsigned long int)inet_accept_org);
  return 0;
}

static void __exit null_exit(void) {
  unsigned long orig_cr0;
  orig_cr0 = read_cr0();
  mywrite_cr0(orig_cr0 & (~0x10000));
  inet_stream_ops->accept = inet_accept_org;
  mywrite_cr0(orig_cr0);
}

module_init(hello_init);
module_exit(null_exit);
