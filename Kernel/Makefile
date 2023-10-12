obj-m := detection_module.o
detection_module-y += src/module_main.o
detection_module-y += src/hidden_modules.o
detection_module-y += src/kfunc_integrity.o
detection_module-y += src/table_integrity.o
detection_module-y += src/vfs_integrity.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
ccflags-y += -I$(dir $(abspath $(lastword $(MAKEFILE_LIST))))/include

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -rf *.ko *.mod.* *.o *.order *.symvers src/*.o