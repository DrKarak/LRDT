#include <linux/module.h>
#include <linux/string.h>
#include <linux/version.h>
#include "module_main.h"
#include "hidden_modules.h"

/*
    Check if module is in THIS_MODULE

    @param name module name
    @return non-zero value if true
*/
int module_is_visible(char *name) {
    struct module *pos, *n;
    int vis = 0;

    list_for_each_entry_safe(pos, n, THIS_MODULE->list.prev, list) {
        if (strcmp(n->name, name) == 0) {
            vis = 1;
        }
    }

    return vis;
}

/*
    Scan for modules hiding from /proc/modules (inspired by Volatility)

    @return number of hidden modules
*/
int hidden_modules_scan(void) {
    struct kset *ks;
    struct kobject *pos, *n;
    struct module_kobject *ko;
    int found = 0;

    ks = (void*)ks_lookup_name("module_kset");
    if (ks == 0) {
        log_msg("Failed to obtain module list", -1);
        return -1;
    }

    list_for_each_entry_safe(pos, n, &ks->list, entry) {
        if (kobject_name(n) == NULL) break;

        ko = container_of(n, struct module_kobject, kobj);

        if (ko != NULL && ko->mod != NULL && ko->mod->name != NULL) {
            if (module_is_visible(ko->mod->name) == 0 && 
                strcmp(THIS_MODULE->name, ko->mod->name) != 0) {
            	log_msg("Module '%s' is hiding from /proc/modules", 3, ko->mod->name);
                found++;
            }
        }
    }

    return found;
}

/*
    Get module name from address

    @param addr address
    @return name
*/
char *get_module_name_from_addr(unsigned long addr) {
    struct kset *ks;
    struct kobject *kpos, *kn;
    struct module_kobject *ko;
    char *name = NULL;

    ks = (void*)ks_lookup_name("module_kset");
    if (ks == 0) {
        log_msg("Failed to obtain module list", -1);
        return NULL;
    }

    list_for_each_entry_safe(kpos, kn, &ks->list, entry) {
        if (kobject_name(kn) == NULL) break;

        ko = container_of(kn, struct module_kobject, kobj);

        if (ko != NULL && ko->mod != NULL) {
            #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
                if ((uintptr_t)addr >= (uintptr_t)ko->mod->core_layout.base &&
                    (uintptr_t)addr < ((uintptr_t)ko->mod->core_layout.base + (uintptr_t)ko->mod->core_layout.size)) {
			        name = ko->mod->name;
		        }
            #else
                if ((uintptr_t)addr >= (uintptr_t)ko->mod->module_core &&
                    (uintptr_t)addr < ((uintptr_t)ko->mod->module_core + (uintptr_t)ko->mod->core_size)) {
			        name = ko->mod->name;
		        }
            #endif
        }
    }

    return name;
}