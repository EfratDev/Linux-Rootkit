#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");

static int __init hello_init(void) {
  printk(KERN_INFO "Hello, World!\n");
  return 0;
}

static void __exit null_exit(void) {}

module_init(hello_init);
module_exit(null_exit);
