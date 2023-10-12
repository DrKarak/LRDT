# Linux Rootkit Detection Toolbox

A collection of rootkit scanners inspired and adapted from chkrootkit, Unhide, OSSEC and Volatility.

### Features

- Uncover kernel modules hiding from /proc/modules (lsmod)
- Verify the integrity of system calls and interrupt handlers
- Verify the integrity of vfs operations (including /proc/net/*)
- Verify the integrity of various additional kernel functions
- Search for hidden directories, processes and network ports
- Find malicious libraries in process maps and preload files/variables
- Search for strings and file paths of known rootkits
- Find suspicious users with elevated privileges
- Find kernel modules persisting via config files

### Installation \& Usage

```bash
# clone repository
git clone https://github.com/DrKarak/LRDT.git
cd LRDT

# install dependencies (gcc, make, net-tools, linux-headers-*)
sudo ./depinstall.sh

# build
./build.sh

# run
sudo ./scan --help
```

The detector provides a variety of different scanning modules which can be used independently or in unison.\
Simply running `sudo ./scan` will enable ALL modules by default.

Please note that, depending on your hardware, some scans may take up to 5 minutes or longer.\
Significantly longer scan times could be an indication of rootkit infection.

### References

https://github.com/YJesus/Unhide \
https://github.com/ossec/ossec-hids/tree/master/src/rootcheck \
https://github.com/volatilityfoundation/volatility/wiki/Linux-Command-Reference#rootkit-detection \
https://www.chkrootkit.org/download/ \
https://github.com/m0nad/Diamorphine \
https://github.com/cofyc/argparse \
https://lloydrochester.com/post/c/c-timestamp-epoch/

Credits to *ssdeep* for their amazing fuzzy-hashing library: https://github.com/ssdeep-project/ssdeep