#include <asm/asm-offsets.h>
#include <linux/version.h>
#include "module_main.h"
#include "hidden_modules.h"
#include "table_integrity.h"

/*
    Scan for manipulated system calls (inspired by Volatility)

    @return number of hooked system calls
*/
int syscall_integrity_scan(void) {
    unsigned long *syscall_table;
    unsigned long addr;
    char *name;
    int i, hooks = 0;

    syscall_table = (void *)ks_lookup_name("sys_call_table");
    if (syscall_table == NULL) {
        log_msg("Failed to obtain system call table", -1);
        return -1;
    }

    for (i = 0; i < NR_syscalls; i++) {
        addr = jump_hook((unsigned long)syscall_table[i]);

        if (kernel_text(addr) == 0) {
            name = get_module_name_from_addr(addr);
            if (name != NULL) {
                log_msg("System call %i has been hooked by %s [%p]", 3, i, name, (void *)addr);
            } else {
                log_msg("System call %i has been hooked by an unknown module [%p]", 3, i, (void *)addr);
            }
            hooks++;
        }
    }

    return hooks;
}

/*
    Scan for manipulated interrupt handlers (inspired by Volatility)

    @return number of hooked interrupt handlers
*/
int interrupt_integrity_scan(void) {
    #if LINUX_VERSION_CODE > KERNEL_VERSION(4, 13, 16)
        struct gate_struct *interrupt_table;
    #else
        struct gate_struct64 *interrupt_table;
    #endif
    unsigned long addr;
    char *name;
    int i, hooks = 0;

    interrupt_table = (void *)ks_lookup_name("idt_table");
    if (interrupt_table == NULL) {
        log_msg("Failed to obtain interrupt descriptor table table", -1);
        return -1;
    }

    for (i = 0; i < IDT_ENTRIES; i++) {
        if (i >= 20 && i <= 31) continue;

        #if LINUX_VERSION_CODE > KERNEL_VERSION(4, 13, 16)
            addr = gate_segment(&interrupt_table[i]) + gate_offset(&interrupt_table[i]);
        #else
            addr = gate_segment(interrupt_table[i]) + gate_offset(interrupt_table[i]);
        #endif

        if (kernel_text(addr) == 0) {
            name = get_module_name_from_addr(addr);
            if (name != NULL) {
                log_msg("Interrupt handler %i has been hooked by %s [%p]", 3, i, name, (void *)addr);
            } else {
                log_msg("Interrupt handler %i has been hooked by an unknown module [%p]", 3, i, (void *)addr);
            }
            hooks++;
        }
    }

    return hooks;
}