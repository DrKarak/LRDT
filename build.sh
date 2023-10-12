#!/bin/sh

[ -e $PWD/scan ] && rm -r $PWD/scan
[ -e $PWD/detection_module.ko ] && rm -r $PWD/detection_module.ko

make clean -C $PWD/Kernel
make -C $PWD/Kernel

make clean -C $PWD/User
make -C $PWD/User

mv $PWD/Kernel/detection_module.ko $PWD/detection_module.ko
mv $PWD/User/scan $PWD/scan

if [ -f $PWD/scan ] && [ -f $PWD/detection_module.ko ]; then
    echo "\033[0;32mBuild finished. Run 'sudo ./scan --help' to get started.\033[0m"
    exit
fi

echo "\033[0;31mBuild failed. Please ensure all dependencies have been installed.\033[0m"