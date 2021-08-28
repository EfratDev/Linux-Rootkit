#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/net.h>
#include <net/sock.h>

#define BLOCK_IP "X.X.X.X"

MODULE_LICENSE("GPL");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef int (*inet_accept_t)(struct socket *sock, struct socket *newsock, int flags, bool kern);

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

struct proto_ops * inet_stream_ops;
inet_accept_t inet_accept_org;
extern unsigned long __force_order;
static inline void mywrite_cr0(unsigned long value) {
  asm volatile("mov %0,%%cr0":"+r"(value),"+m"(__force_order));
}

unsigned int inet_addr(char *str) {
  int a, b, c, d;
  char arr[4];
  sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
  arr[0] = a;
  arr[1] = b;
  arr[2] = c;
  arr[3] = d;
  return *(unsigned int *)arr;
}

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
  unsigned int client_address;
  fd = inet_accept_org(sock, newsock, flags, kern);
  client_address = (unsigned int) newsock->sk->__sk_common.skc_daddr;

  if (client_address == inet_addr(BLOCK_IP)) {
    return -EINVAL;
  }
 
  return fd;
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
