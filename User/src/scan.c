#define _GNU_SOURCE
#define __USE_XOPEN
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <argp.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include "message.h"
#include "hidden_files.h"
#include "hidden_ports.h"
#include "hidden_procs.h"
#include "injected_libraries.h"
#include "misc_checks.h"
#include "scan.h"

const char *argp_program_version = "Linux Rootkit Detection Toolbox v1.0";
static char doc[] = "A collection of scanners for detecting various linux rootkits";

/*
    Descriptions for help page
*/
static struct argp_option options[] = { 
    { "all", 'A', 0, 0, "Enable all scans (default)", 0},
    { "exclude", 'X', 0, 0, "Invert scanner selection", 0},
    { "modules", 'm', 0, 0, "Search for modules hiding from /proc/modules", 1},
    { "syscall", 's', 0, 0, "Verify the integrity of all system calls", 1},
    { "interrupt", 'i', 0, 0, "Verify the integrity of all interrupt handlers", 1},
    { "fops", 'f', 0, 0, "Verify the integrity of vfs file operations", 1},
    { "net", 'n', 0, 0, "Verify the integrity of /proc/net", 1},
    { "kfunc", 'k', 0, 0, "Verify the integrity of various kernel functions", 1},
    { "dirs", 'd', 0, 0, "Search for hidden directories", 2},
    { "ports", 'p', 0, 0, "Search for hidden network ports", 2},
    { "procs", 'P', 0, 0, "Search for hidden processes", 2},
    { "libs", 'l', 0, 0, "Search for processes mapping known rootkit libraries", 2},
    { "env", 'e', 0, 0, "Check preload enviroment variables", 2},
    { "etc", 'E', 0, 0, "Check preload file entries", 2},
    { "string", 'g', 0, 0, "Search files for known rootkit strings", 2},
    { "path", 't', 0, 0, "Search for known rootkit file paths", 2},
    { "persist", 'T', 0, 0, "Check config files for persisting modules", 2},
    { "root", 'r', 0, 0, "Search for non-root users with elevated privileges", 2},
    { 0 }
};

struct arguments {
    short int s_hlink;
    short int s_ports;
    short int s_procs;
    short int s_maps;
    short int s_prefile;
    short int s_var;
    short int s_string;
    short int s_path;
    short int s_persist;
    short int s_root;
    short int s_modules;
    short int s_syscall;
    short int s_interrupt;
    short int s_fops;
    short int s_net;
    short int s_kfunc;
    short int m_exclude;
};

struct arguments arguments;

int warning, alert, error;
int module_loaded;

/*
    Load kernel module from current working directory

    @return non-zero value on error
*/
int load_module(void) {
    int fd, ret;
    char flags[95];

    fd = open("./detection_module.ko", O_RDONLY);
    if (fd < 0) {
        ERROR("Unable to open './detection_module.ko' (please ensure the file exists and is readable)")
        return -1;
    }

    snprintf(flags, 95, "s_modules=%i s_syscall=%i s_interrupt=%i s_fops=%i s_net=%i s_kfunc=%i",
            arguments.s_modules, arguments.s_syscall, arguments.s_interrupt, 
            arguments.s_fops, arguments.s_net, arguments.s_kfunc);

    ret = syscall(__NR_finit_module, fd, flags, 0);
    close(fd);
    return ret;
}

/*
    Unload kernel module

    @return non-zero value on error
*/
int remove_module(void) {
    return syscall(__NR_delete_module, "detection_module", O_NONBLOCK);
}

/*
    Check if kernel module is loaded by reading /proc/modules

    @return value >0 if loaded
*/
int module_is_loaded(void) {
    FILE* fp;
    char buf[512];
    int loaded = 0;

    fp = fopen("/proc/modules", "r");
    if (fp == NULL) {
        ERROR("Unable to open /proc/modules")
        return -1;
    }

    while (fgets(buf, 512, fp) != NULL) {
        if ((strstr(buf, "detection_module")) != NULL) {
            loaded = 1;
        }
    }

    fclose(fp);
    return loaded;
}

/*
    Read and print all messages from the procfs interface
*/
void print_procfs_msg_buffer(void) {
    int fd, size;
    char buf[257];

    while (1) {
        fd = open("/proc/detection_module", O_RDONLY);
        if (fd < 0) {
            ERROR("Unable to open procfs interface. Please use 'dmesg' to read kernel output")
            break;
        }

        if ((size = read(fd, buf, 256)) <= 0) break;
        buf[size] = '\0';

        if (strncmp("OK", buf, 2) == 0) {
            OK("%s", buf+2);
        } else if (strncmp("ERR", buf, 3) == 0) {
            ERROR("%s", buf+3);
        } else if (strncmp("WARN", buf, 4) == 0) {
            WARNING("%s", buf+4);
        } else if (strncmp("ALRT", buf, 4) == 0) {
            ALERT("%s", buf+4);
        } else {
            DIV
            INFO("%s", buf)
        }
        
        close(fd);
    }
}

/*
    Get current ISO 8601 timestamp (adapted from Lloyd Rochester's Geek Blog)
*/
char *rfc8601_timespec(struct timespec *tv, char *rfc8601) {
  char time_str[127];
  double fractional_seconds;
  int milliseconds;
  struct tm tm;

  memset(&tm, 0, sizeof(struct tm));
  sprintf(time_str, "%ld UTC", tv->tv_sec);

  strptime(time_str, "%s %U", &tm);

  fractional_seconds = (double)tv->tv_nsec;
  fractional_seconds /= 1e6;
  fractional_seconds = (int)fractional_seconds+0.5;
  milliseconds = (int)fractional_seconds;

  strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", &tm);

  sprintf(rfc8601, "%s.%dZ", time_str, milliseconds);

  return rfc8601;
}

/*
    Enable all scanners
*/
void enable_all(void) {
    arguments.s_hlink = arguments.s_ports = 
    arguments.s_procs = arguments.s_maps = 
    arguments.s_prefile = arguments.s_var = 
    arguments.s_string = arguments.s_path =
    arguments.s_persist = arguments.s_root = 
    arguments.s_modules = arguments.s_syscall = 
    arguments.s_interrupt = arguments.s_fops = 
    arguments.s_net = arguments.s_kfunc = 1;
}

/*
    Invert scanner selection
*/
void invert_args(void) {
    arguments.s_hlink--; arguments.s_ports--; 
    arguments.s_procs--; arguments.s_maps--; 
    arguments.s_prefile--; arguments.s_var--; 
    arguments.s_string--; arguments.s_path--;
    arguments.s_persist--; arguments.s_root--; 
    arguments.s_modules--; arguments.s_syscall--; 
    arguments.s_interrupt--; arguments.s_fops--; 
    arguments.s_net--; arguments.s_kfunc--;
}

/*
    Parse commandline arguments using argparse
*/
static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *args = state->input;
    switch (key) {
        case 'A': enable_all(); break;
        case 'X': args->m_exclude = 1; break;
        case 'm': args->s_modules = 1; break;
        case 's': args->s_syscall = 1; break;
        case 'i': args->s_interrupt = 1; break;
        case 'f': args->s_fops = 1; break;
        case 'n': args->s_net = 1; break;
        case 'k': args->s_kfunc = 1; break;
        case 'd': args->s_hlink = 1; break;
        case 'p': args->s_ports = 1; break;
        case 'P': args->s_procs = 1; break;
        case 'l': args->s_maps = 1; break;
        case 'e': args->s_var = 1; break;
        case 'E': args->s_prefile = 1; break;
        case 'g': args->s_string = 1; break;
        case 't': args->s_path = 1; break;
        case 'T': args->s_persist = 1; break;
        case 'r': args->s_root = 1; break;
        case ARGP_KEY_ARG: return 0;
        default: return ARGP_ERR_UNKNOWN;
    }   
    return 0;
}

/*
    Unload kernel module upon unexpected exit (e.g. Ctrl+c)
*/
void exit_cleanup(int sig) {
    if (module_loaded != 0) {
        INFO("Scan interrupted. Cleaning up...")

        if (remove_module() != 0) {
            ERROR("Unable to remove 'detection_module'. Please unload manually using 'rmmod'")
        } else {
            OK("Kernel module removed")
        }
    }
    exit(EXIT_SUCCESS);
}

static struct argp argp = { options, parse_opt, 0, doc, 0, 0, 0 };

/*
    Run enabled scanners and print output
*/
int main(int argc, char *argv[]) {

    struct timespec tv;
    char rfc8601[256];
    module_loaded = 0;
    warning = alert = error = 0;

    signal(SIGINT, exit_cleanup);

    argp_parse(&argp, argc, argv, 0, 0, &arguments);
    if (argc == 1) enable_all();
    if (arguments.m_exclude != 0) invert_args();

    if (geteuid() != 0) {
        FATAL("This program requires root priviliges to run")
        exit(EXIT_FAILURE);
    }

    if (clock_gettime(CLOCK_REALTIME, &tv) == 0) {
        rfc8601_timespec(&tv, rfc8601);
        INFO("Scan started at %s", rfc8601)
    }

    if (arguments.s_modules != 0 || arguments.s_syscall != 0 || 
        arguments.s_interrupt != 0 || arguments.s_fops != 0 || 
        arguments.s_net != 0 || arguments.s_kfunc != 0) {

        if (module_is_loaded() <= 0) {
            INFO("Kernel module not loaded. Loading...")

            if (load_module() != 0) {
                FATAL("Failed to load 'detection_module'. Check 'dmesg' output for errors!")
            } else {
                OK("Kernel module loaded")
                module_loaded = 1;
            }
        } else {
            WARNING("Kernel module already loaded. Please note that the module must be reloaded between scans!")
            module_loaded = 1;
        }

        if (module_loaded != 0) {
            print_procfs_msg_buffer();
        } else {
            ERROR("Kernel module not loaded. Skipping kernel scans!")
        }
    }

    DIV

    if (arguments.s_hlink != 0) {
        INFO("Searching for hidden directories...")

        if (hidden_hlink_scan("/", 0) +
            hidden_hlink_scan("/home", 1) +
            hidden_hlink_scan("/tmp", 1) +
            hidden_hlink_scan("/lib", 1) +
            hidden_hlink_scan("/bin", 1) +
            hidden_hlink_scan("/dev", 1) +
            hidden_hlink_scan("/etc", 1) <= 0) {
            OK("No hidden directories found")
        }

        DIV
    }

    if (arguments.s_ports != 0) {
        INFO("Searching for hidden network ports...")

        if (hidden_ports_scan() == 0) {
            OK("No hidden ports found")
        }

        DIV
    }

    if (arguments.s_procs != 0) {
        INFO("Searching for hidden processes...")

        if (hidden_procs_scan() == 0) {
            OK("No hidden processes found")
        }

        DIV
    }
    
    if (arguments.s_maps != 0) {
        INFO("Searching for known rootkit libraries...")

        if (proc_maps_lib_scan() == 0) {
            OK("No known libraries found")
        }

        DIV
    }

    if (arguments.s_var != 0) {
        INFO("Checking preload variables...")

        preload_var_check();

        DIV
    }

    if (arguments.s_prefile != 0) {
        INFO("Checking preload file entries...")

        if (preload_file_check() == 0) {
            OK("No library entries found")
        }

        DIV
    }

    if (arguments.s_string != 0) {
        INFO("Searching for known strings...")

        if (known_strings_scan() == 0) {
            OK("No known strings found")
        }

        DIV
    }

    if (arguments.s_path != 0) {
        INFO("Searching for known paths...")

        if (known_paths_scan() == 0) {
            OK("No known paths found")
        }

        DIV
    }

    if (arguments.s_persist != 0) {
        INFO("Searching for persisting modules...")

        if (module_persist_scan() == 0) {
            OK("No persisting modules found")
        }

        DIV
    }

    if (arguments.s_root != 0) {
        INFO("Searching for suspicious users...")

        if (root_users_check() == 0) {
            OK("No suspicious users found")
        }

        DIV
    }

    if (module_loaded != 0) {
        INFO("Cleaning up...")

        if (remove_module() != 0) {
            ERROR("Unable to remove 'detection_module'. Please unload manually using 'rmmod'")
        } else {
            OK("Kernel module removed")
        }
    }

    if (clock_gettime(CLOCK_REALTIME, &tv) == 0) {
        rfc8601_timespec(&tv, rfc8601);
        INFO("Scan concluded at %s", rfc8601)
    }

    DIV

    if (alert > 0) {
        printf("\033[1;31mPossible rootkit infection detected! Take immediate action.\033[0m\n");
    } else if (warning > 0) {
        printf("\033[0;93mSuspicous behaviour/configuration found.\nPlease ensure all warnings are intended or false positives.\033[0m\n");
    } else {
        printf("\033[0;32mNo signs of infection found.\033[0m\nPlease note that no tool can ever guarantee a 100%% clean system.\n");
    }

    if (error > 0) {
        printf("\033[0;31mError(s) occured during execution.\nThis may have impacted detection results.\033[0m\n");
    }

    exit(EXIT_SUCCESS);
}