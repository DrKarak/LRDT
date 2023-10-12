#include <linux/module.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include "hidden_modules.h"
#include "kfunc_integrity.h"
#include "table_integrity.h"
#include "vfs_integrity.h"
#include "module_main.h"

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 13, 19)
    #include <linux/stdarg.h>
#endif

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Kernel rootkit detection module");

static short int s_modules;
static short int s_syscall;
static short int s_interrupt;
static short int s_fops;
static short int s_net;
static short int s_kfunc;

module_param(s_modules, short, S_IRUSR);
MODULE_PARM_DESC(s_modules, "Search for modules hiding from /proc/modules");

module_param(s_syscall, short, S_IRUSR);
MODULE_PARM_DESC(s_syscall, "Verify the integrity of all system calls");

module_param(s_interrupt, short, S_IRUSR);
MODULE_PARM_DESC(s_interrupt, "Verify the integrity of all interrupt handlers");

module_param(s_fops, short, S_IRUSR);
MODULE_PARM_DESC(s_fops, "Verify the integrity of vfs file operations");

module_param(s_net, short, S_IRUSR);
MODULE_PARM_DESC(s_net, "Verify the integrity of /proc/net");

module_param(s_kfunc, short, S_IRUSR);
MODULE_PARM_DESC(s_kfunc, "Verify the integrity of various kernel functions");

int (*kernel_text)(unsigned long addr);

LIST_HEAD(messages);

typedef struct msg_buffer {
    char msg[256];
    struct list_head list;
} msg_buffer;

/*
    Add message to buffer

    @param msg message
*/
void add_msg(char *msg) {
    struct msg_buffer *new = kmalloc(sizeof(struct msg_buffer), GFP_KERNEL);
    memcpy(new->msg, msg, 256);
    list_add_tail(&new->list, &messages);
}

/*
    Free the entire message buffer
*/
void free_messages(void) {
    struct msg_buffer *pos, *n;

    list_for_each_entry_safe(pos, n, &messages, list) {
        list_del(&pos->list);
        kfree(pos);
    }
}

/*
    Log messages to buffer and kernel logs

    @param msg message
    @param type type

    -1 = ERROR
    1 = OK
    2 = WARNING
    3 = ALERT
*/
void log_msg(char *msg, int type, ...) {
    va_list args;
    char buf[256], form[256];

    va_start(args, type);
    vsnprintf(form, 256, msg, args);
    va_end(args);

    switch(type) {
        case -1:
            printk(KERN_ERR "%s\n", form);
            snprintf(buf, 256, "ERR%s", form);
            break;
        case 1:
            printk(KERN_INFO "%s\n", form);
            snprintf(buf, 256, "OK%s", form);
            break;
        case 2:
            printk(KERN_WARNING "%s\n", form);
            snprintf(buf, 256, "WARN%s", form);
            break;
        case 3:
            printk(KERN_WARNING "%s\n", form);
            snprintf(buf, 256, "ALRT%s", form);
            break;
        default:
            printk(KERN_INFO "%s\n", form);
            snprintf(buf, 256, "%s", form);
            break;
    }

    add_msg(buf);
}

ks_lookup_name_t ks_lookup_name;

static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};

/*
    Get pointer to kallsyms_lookup_name (adapted from Diamorphine)
*/
void init_ks_lookup_name(void) {
	register_kprobe(&kp);
	ks_lookup_name = (ks_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);
}

static struct proc_dir_entry *detection_module_procfs_entry;

/*
    Return messages from buffer over procfs interface
*/
static ssize_t detection_module_procfs_read(struct file *fp, char __user *buf, size_t count, loff_t *offset) {
    struct msg_buffer *m;
    int len;

    if (list_empty(&messages) != 0) return 0;

    m = list_first_entry(&messages, struct msg_buffer, list);
    len = strlen(m->msg);

    if (copy_to_user(buf, m->msg, len) != 0) return -EFAULT;

    list_del(&m->list);
    kfree(m);

    if (*offset != 0) return 0;

    *offset += 1;
    return (ssize_t)len;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
    static struct file_operations detection_module_procfs_fops = {
        .read = detection_module_procfs_read
    };
#else
    static struct proc_ops detection_module_procfs_fops = {
        .proc_read = detection_module_procfs_read
    };
#endif

/*
    Initialize procfs interface

    @return non-zero value if successful
*/
int detection_module_procfs_entry_init(void) {
    detection_module_procfs_entry = proc_create("detection_module", 0666, NULL, &detection_module_procfs_fops);
    if (detection_module_procfs_entry == NULL) return 0;
    return 1;
}

/*
    Find jump hooks and return "true" function pointers
    
    @param addr function pointer
    @return "true" function pointer
*/
unsigned long jump_hook(unsigned long addr) {
    unsigned char buf[12];
    unsigned long off = 0;

    do {
        memcpy(buf, (void *)addr + off++, 12);
    } while (buf[0] == 0x90);

    #if defined __x86_64__
        if (buf[0] == 0xe9 || buf[0] == 0xcc) {
            memcpy(&addr, buf + 1, 8);
        } else if (buf[0] == 0x48 && buf[1] == 0xb8 && buf[10] == 0xff && buf[11] == 0xe0) {
            memcpy(&addr, buf + 2, 8);
        }
    #elif defined __i386__
        if (buf[0] == 0x68 && buf[5] == 0xc3) {
            memcpy(&addr, buf + 1, 4);
        }
    #endif

    return addr;
}

/*
    Check if core_kernel_text function has manipulated

    @return non-zero value if manipulated
*/
int verify_core_kernel_text(void) {
    unsigned long addr;
    char *name;

    addr = jump_hook((unsigned long)kernel_text);

    if (addr != (unsigned long)kernel_text) {
        name = get_module_name_from_addr(addr);
        if (name != NULL) {
            log_msg("The core_kernel_text function has been hooked by %s [%p]", 3, name, (void *)addr);
        } else {
            log_msg("The core_kernel_text function has been hooked by an unknown module [%p]", 3, (void *)addr);
        }
        return 1;
    }

    if ((name = get_module_name_from_addr(addr)) != NULL) {
        log_msg("The core_kernel_text function has been hooked by %s [%p]", 3, name, (void *)addr);
        return 1;
    }

    return 0;
}

/*
    Initialize kernel module and run enabled scanners
*/
static int __init detection_module_init(void) {

    init_ks_lookup_name();
    if (ks_lookup_name == NULL) {
        log_msg("Failed to obtain kallsyms_lookup_name", -1);
        return -1;
    }

    kernel_text = (void *)ks_lookup_name("core_kernel_text");
    if (kernel_text == NULL) {
        log_msg("Failed to obtain core_kernel_text", -1);
        return -1;
    }
    if (verify_core_kernel_text() != 0) {
        log_msg("The core_kernel_text function has been compromised!", 3);
        return -1;
    }

    if (detection_module_procfs_entry_init() == 0) {
        log_msg("Failed to register procfs entry", -1);
        return -1;
    }

    if (s_modules != 0) {
        log_msg("Searching for hidden modules...", 0);
        if (hidden_modules_scan() == 0) log_msg("No hidden modules found", 1);
    }

    if (s_syscall != 0) {
        log_msg("Verifying system call integrity...", 0);
        if (syscall_integrity_scan() == 0) log_msg("No system calls hooked", 1);
    }

    if (s_interrupt != 0) {
        log_msg("Verifying interrupt handler integrity...", 0);
        if (interrupt_integrity_scan() == 0) log_msg("No interrupt handlers hooked", 1);
    }

    if (s_fops != 0) {
        log_msg("Verifying file operation integrity...", 0);
        if (fops_integrity_scan() == 0) log_msg("No file operations hooked", 1);
    }

    if (s_net != 0) {
        log_msg("Verifying /proc/net integrity...", 0);
        if (proc_net_integrity_scan() == 0) log_msg("No /proc/net functions hooked", 1);
    }

    if (s_kfunc != 0) {
        log_msg("Verifying kernel function integrity...", 0);
        if (kernel_function_scan() == 0) log_msg("No hooks found", 1);
    }

    printk(KERN_INFO "Rootkit detection module initialized\n");

    return 0;
}

/*
    Cleanup message buffer and procfs interface on exit
*/
static void __exit detection_module_exit(void) {
    free_messages();
    proc_remove(detection_module_procfs_entry);
    printk(KERN_INFO "Rootkit detection module exited\n");
}

module_init(detection_module_init);
module_exit(detection_module_exit);