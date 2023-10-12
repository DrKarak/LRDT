#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include "scan.h"
#include "message.h"
#include "fuzzy.h"
#include "injected_libraries.h"

/*
    Check if directory entry belongs to a process

    @param entry directory entry
    @return non-zero value if true
*/
int is_proc_dir(struct dirent *entry) {
    int i, num = 1;
    for (i = 0; i < strlen(entry->d_name); i++) {
        if (isdigit(entry->d_name[i]) == 0) num = 0;
    }
    return num && entry->d_type == DT_DIR;
}

/*
    Check if shared object is a known library

    @param path  filepath of shared object
    @param fp    file pointer to ssdeep database
    @param rtlib buffer for return value
*/
void is_known_lib(char *path, FILE *fp, char *rtlib) {
    char sig[FUZZY_MAX_RESULT], fuzzy[FUZZY_MAX_RESULT], kit[128];
    struct stat st;

    memset(rtlib, 0, 4096);

    path[strcspn(path, "\n")] = 0;

    lstat(path, &st);
    if (S_ISREG(st.st_mode) == 0) return;

    fuzzy_hash_filename(path, fuzzy);

    while (fscanf(fp, "%148s %128s", sig, kit) > 0) {
        if (fuzzy_compare(sig, fuzzy) > 80) {
            snprintf(rtlib, 4096, "'%s' [%s]", kit, path);
            break;
        }
    }

    rewind(fp);
}

/*
    Scan mappings of processes for known libraries

    @return number of hooked processes
*/
int proc_maps_lib_scan(void) {
    char path_buf[PATH_MAX], prev_buf[PATH_MAX];
    char rtlib[4096];
    char *off;
    char *lib_buf = NULL;
    size_t size = 0;
    struct dirent* entry;
    DIR* dirp;
    FILE *fp, *fpk;
    int known = 0;

    dirp = opendir("/proc");
    if (dirp == NULL) {
        ERROR("Failed to open /proc")
        return 0;
    }

    fpk = fopen("./Data/known_libs.txt", "r");
    if (fpk == NULL) {
        ERROR("Failed to read known libraries")
        return 0;
    }

    while ((entry = readdir(dirp)) != 0) {
        if (is_proc_dir(entry) != 0) {
            snprintf(path_buf, PATH_MAX, "/proc/%s/maps", entry->d_name);
            
            fp = fopen(path_buf, "r");
            if (fp == NULL) continue;

            while (getline(&lib_buf, &size, fp) != -1) {

                off = strchr(lib_buf, '/');
                if (off == NULL) continue;
                
                if (strcmp(off, prev_buf) == 0) continue;
                else memcpy(prev_buf, off, PATH_MAX);

                is_known_lib(off, fpk, rtlib);
                if (strlen(rtlib) > 0) {
                    ALERT("Process %s maps library of known rootkit %s", entry->d_name, rtlib);
                    known++;
                    break;
                }
            }

            fclose(fp);
            memset(path_buf, 0, PATH_MAX);
        }
    }

    closedir(dirp);
    fclose(fpk);
    free(lib_buf);
    return known;
}

/*
    Check ld.so.preload for (known) libraries

    @return number of found libraries
*/
int preload_file_check(void) {
    FILE *fp, *fpk;
    char buf;
    char path_buf[PATH_MAX], rtlib[4096];
    int load = 0;

    fp = fopen("/etc/ld.so.preload", "r");

    if (fp == NULL) {
        INFO("/etc/ld.so.preload doesn't exist or can't be opened")
        return 0;
    }

    fpk = fopen("./Data/known_libs.txt", "r");
    if (fpk == NULL) {
        ERROR("Failed to read known libraries")
    }

    memset(path_buf, 0, PATH_MAX);

    while (!feof(fp)) {
        buf = fgetc(fp);
        if (strncmp(" ", &buf, 1) == 0 
            || strncmp(";", &buf, 1) == 0 
            || strncmp("\n", &buf, 1) == 0
            || strncmp("\0", &buf, 1) == 0) {

            if (strcmp("\0", &path_buf[0])) {
                if (fpk != NULL) is_known_lib(path_buf, fpk, rtlib);
                if (strlen(rtlib) > 0) {
                    ALERT("/etc/ld.so.preload preloads library of known rootkit %s", rtlib)
                } else {
                    WARNING("/etc/ld.so.preload preloads library %s", path_buf)
                }
                load++;
            }
            memset(path_buf, 0, PATH_MAX);
        } else {
            strncat(path_buf, &buf, 1);
        }
    }

    fclose(fp);
    fclose(fpk);
    return load;
}

/*
    Check if LD_PRELOAD or LD_LIBRARY_PATH are set

    @return number of variables
*/
int preload_var_check(void) {
    char *preload_var, *library_var;
    int set = 0;

    preload_var = getenv("LD_PRELOAD");
    library_var = getenv("LD_LIBRARY_PATH");

    if (preload_var != NULL) {
        WARNING("LD_PRELOAD is set to '%s'", preload_var)
        set += 1;
    } else {
        OK("LD_PRELOAD is not set")
    }

    if (library_var != NULL) {
        WARNING("LD_LIBRARY_PATH is set to '%s'", library_var)
        set += 1;
    } else {
        OK("LD_LIBRARY_PATH is not set")
    }

    return set;
}