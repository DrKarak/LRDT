#ifndef DETECTION_MODULE_H
#define DETECTION_MODULE_H

#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 13, 19)
    #include <linux/stdarg.h>
#endif

extern int (*kernel_text)(unsigned long addr);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
    typedef int (*proc_write_t)(struct file *, char *, size_t);
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 11, 0)
    typedef struct refcount_struct {
        atomic_t refs;
    } refcount_t;
#endif

struct proc_dir_entry {
    atomic_t in_use;
    refcount_t refcnt;
    struct list_head pde_openers;
    spinlock_t pde_unload_lock;
    struct completion *pde_unload_completion;
    const struct inode_operations *proc_iops;
    const struct file_operations *proc_fops;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 29)
        const struct dentry_operations *proc_dops;
    #endif
    union {
        const struct seq_operations *seq_ops;
        int (*single_show)(struct seq_file *, void *);
    };
    proc_write_t write;
    void *data;
    unsigned int state_size;
    unsigned int low_ino;
    nlink_t nlink;
    kuid_t uid;
    kgid_t gid;
    loff_t size;
    struct proc_dir_entry *parent;
    struct rb_root subdir;
    struct rb_node subdir_node;
    char *name;
    umode_t mode;
    u8 namelen;
    char inline_name[];
};

typedef unsigned long (*ks_lookup_name_t)(const char *name);
extern ks_lookup_name_t ks_lookup_name;

void log_msg(char* msg, int type, ...);
unsigned long jump_hook(unsigned long addr);

#endif