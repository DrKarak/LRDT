#include <linux/net.h>
#include <net/net_namespace.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include "module_main.h"
#include "hidden_modules.h"
#include "vfs_integrity.h"

/*
    Verify integrity of file operation

    @param op_name file operation name
    @param path    filesystem path
    @param addr    file operation address
    @return non-zero value if violated
*/
int verify_op(char *op_name, char *path, unsigned long addr) {
    char *name;

    if (op_name == NULL || path == NULL || addr == 0) return 0;

    if (kernel_text(jump_hook(addr)) == 0) {
        name = get_module_name_from_addr(addr);
        if (name != NULL) {
            log_msg("VFS '%s' operation of %s has been hooked by %s [%p]", 2, op_name, path, name, (void *)addr);
        } else {
            log_msg("VFS '%s' operation of %s has been hooked by an unknown module [%p]", 2, op_name, path, (void *)addr);
        }
        return 1;
    }
    return 0;
}

/*
    Scan for manipulated file operations (inspired by Volatility)

    @param number of hooked operations
*/
int fops_integrity_scan(void) {
    char *paths[] = {
        "/",
        "/proc",
        "/sys",
        "/dev"
    };
    struct file *fp;
    int i, hooks = 0;

    for (i = 0; i < 4; i++) {
        fp = filp_open(paths[i], O_RDONLY, S_IRUSR);

        if (fp == NULL) {
            log_msg("Unable to open file system %s", -1, paths[i]);
            return 0;
        }
        if (fp->f_op == NULL) {
            log_msg("%s has no file operations", -1, paths[i]);
            return 0;
        }

        #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
            hooks += verify_op("iterate_shared", paths[i], (unsigned long)fp->f_op->iterate_shared);
        #elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0) 
            hooks += verify_op("iterate", paths[i], (unsigned long)fp->f_op->iterate);
        #else
            hooks += verify_op("readdir", paths[i], (unsigned long)fp->f_op->readdir);
        #endif

        hooks += verify_op("read", paths[i], (unsigned long)fp->f_op->read);
        hooks += verify_op("write", paths[i], (unsigned long)fp->f_op->write);
        hooks += verify_op("open", paths[i], (unsigned long)fp->f_op->open);
        hooks += verify_op("llseek", paths[i], (unsigned long)fp->f_op->llseek);
    }

    return hooks;
}

/*
    Get procfs entry from root directory

    @param root tree root (e.g. proc_net)
    @param name entry name
*/
struct proc_dir_entry *get_dir(struct rb_root *root, char *name) {
    struct rb_node *cursor = rb_first(root);
    struct proc_dir_entry *entry;

    while (cursor != NULL) {
        entry = rb_entry(cursor, struct proc_dir_entry, subdir_node);
        if (strcmp(entry->name, name) == 0) return entry;
        cursor = rb_next(cursor);
    }

    return NULL;
}

/*
    Scan for manipulated network interfaces (inspired by Volatility)

    @return number of hooked interfaces
*/
int proc_net_integrity_scan(void) {
    char *entries[] = {
        "tcp",
        "tcp6",
        "udp",
        "udp6"
    };
    char path_buf[256];
    int i, hooks = 0;

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
        const struct seq_operations *s_ops;
        const struct file_operations *f_ops;
        struct proc_dir_entry *entry;

        for (i = 0; i < 4; i++) {
            entry = get_dir(&init_net.proc_net->subdir, entries[i]);
            if (entry == NULL) {
                log_msg("Unable to open entry %s", -1, entries[i]);
                continue;
            }

            s_ops = entry->seq_ops;
            f_ops = entry->proc_fops;

            if (s_ops == NULL || f_ops == NULL) {
                log_msg("%s has no file operations", -1, entries[i]);
                continue;
            }

            snprintf(path_buf, 256, "/proc/net/%s", entries[i]);

            hooks += verify_op("read", path_buf, (unsigned long)f_ops->read);
            hooks += verify_op("release", path_buf, (unsigned long)f_ops->release);
            hooks += verify_op("llseek", path_buf, (unsigned long)f_ops->llseek);
            hooks += verify_op("show", path_buf, (unsigned long)s_ops->show);

            memset(path_buf, 0, 256);
        }
    #else
        struct tcp_seq_afinfo *tcp_afinfo;
        struct udp_seq_afinfo *udp_afinfo;
        struct file *fp;

        for (i = 0; i < 4; i++) {
            snprintf(path_buf, 256, "/proc/net/%s", entries[i]);
            fp = filp_open(path_buf, O_RDONLY, 0); 

            if (fp == NULL) {
                log_msg("Unable to open file %s", -1, path_buf);
                return 0;
            }
            if (fp->f_path.dentry->d_inode == NULL) {
                log_msg("%s has no afino", -1, path_buf);
                return 0;
            }

            if (i < 2) {
                tcp_afinfo = PDE_DATA(fp->f_path.dentry->d_inode);
                hooks += verify_op("show", path_buf, (unsigned long)tcp_afinfo->seq_ops.show);
            } else {
                udp_afinfo = PDE_DATA(fp->f_path.dentry->d_inode);
                hooks += verify_op("show", path_buf, (unsigned long)udp_afinfo->seq_ops.show);
            }

            memset(path_buf, 0, 256);
        }

    #endif

    return hooks;
}