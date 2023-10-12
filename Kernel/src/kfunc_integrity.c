#include "module_main.h"
#include "hidden_modules.h"
#include "kfunc_integrity.h"

/*
    Verfy the integrity of various kernel functions

    @return number of hooked functions
*/
int kernel_function_scan(void) {
    char *functions[] = {
        "find_task_by_vpid",
        "find_task_by_pid_ns",
        "vfs_read",
        "vfs_write",
        "vfs_stat",
        "vfs_lstat",
        "vfs_statx",
        "ip_rcv",
        "tcp_v4_rcv",
        "udp_rcv",
        "raw_rcv",
        "packet_rcv_spkt",
        "tpacket_rcv",
        "packet_rcv",
        "copy_creds",
        "exit_creds",
        "audit_alloc",
        "next_tgid",
        "fillonedir",
        "filldir",
        "filldir64",
        "compat_fillonedir",
        "compat_filldir",
        "compat_filldir64",
        "inet_ioctl",
        "inet_recvmsg",
        "inet_sendmsg",
        "inet_bind",
        "inet_listen",
        "inet_accept"
    };
    unsigned long addr;
    char *name;
    int f = 30;
    int i, hooks = 0;

    for (i = 0; i < f; i++) {
        addr = ks_lookup_name(functions[i]);
        if (addr == 0) continue;

        if (kernel_text(jump_hook(addr)) == 0) {
            name = get_module_name_from_addr(addr);
            if (name != NULL) {
                log_msg("Kernel function %s has been hooked by %s [%p]", 3, functions[i], name, (void *)addr);
            } else {
                log_msg("Kernel function %s has been hooked by an unknown module [%p]", 3, functions[i], (void *)addr);
            }
            hooks++;
        }
    }

    return hooks;
}