#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <pwd.h>
#include "scan.h"
#include "message.h"
#include "misc_checks.h"

/*
    Check if a non-root user with uid/gid == 0 exists

    @return number of found users
*/
int root_users_check(void) {
    struct passwd *entry;
    int found = 0;

    while((entry = getpwent()) != NULL) {
        if ((entry->pw_uid == 0 || entry->pw_gid == 0) && strcmp("root", entry->pw_name) != 0) {
            WARNING("Found non-root user '%s' with UID/GID of 0 [%s]", entry->pw_name, entry->pw_dir)
            found++;
        }
    }

    endpwent();
    return found;
}

/*
    Search files for known strings

    @return number of found files
*/
int known_strings_scan(void) {
    char path[PATH_MAX], string[4096], kit[128], cmd[4107];
    FILE *fpk, *fpp;
    char *string_buf = NULL;
    size_t size = 0;
    char *off;
    int found = 0;

    fpk = fopen("./Data/known_strings.txt", "r");
    if (fpk == NULL) {
        ERROR("Failed to read known strings")
        return -1;
    }

    while (fscanf(fpk, "%4096s %4096s %128s", path, string, kit) > 0) {
        snprintf(cmd, 4107, "strings -a %s", path);

        fpp = popen(cmd, "r");
        if (fpp == NULL) {
            ERROR("Failed to read strings of file '%s'", path)
            continue;
        }

        while (getline(&string_buf, &size, fpp) != -1) {
            string_buf[strcspn(string_buf, "\n")] = 0;
            if (strcmp(string, string_buf) == 0) {
                ALERT("%s contains string of known rootkit '%s' [%s]", path, kit, string)
                found++;
                break;
            }
        }

        fclose(fpp);
    }

    fclose(fpk);
    free(string_buf);
    return found;
}

/*
    Search filesystem for known paths

    @return number of found paths
*/
int known_paths_scan(void) {
    char path[PATH_MAX], kit[128];
    FILE *fpk, *fpr;
    char *off;
    int found = 0;

    fpk = fopen("./Data/known_paths.txt", "r");
    if (fpk == NULL) {
        ERROR("Failed to read known paths")
        return -1;
    }

    while (fscanf(fpk, "%4096s %128s", path, kit) > 0) {
        fpr = fopen(path, "r");
        if (fpr != NULL) {
            ALERT("Found file path of known rootkit '%s' [%s]", kit, path)
            found++;
            fclose(fpr);
        }
    }

    fclose(fpk);
    return found;
}

/*
    Print all modules persisting via config files

    @return number of found modules
*/
int module_persist_scan(void) {
    char path_buf[PATH_MAX];
    char *conf_buf = NULL;
    size_t size = 0;
    struct dirent* entry;
    DIR* dirp;
    FILE *fp;
    int found = 0;

    dirp = opendir("/etc/modules-load.d");
    if (dirp == NULL) {
        ERROR("Failed to open /etc/modules-load.d")
        return 0;
    }

    while ((entry = readdir(dirp)) != 0) {
        if (strncmp(entry->d_name + strlen(entry->d_name) - 5, ".conf", 5) == 0) {
            snprintf(path_buf, PATH_MAX, "/etc/modules-load.d/%s", entry->d_name);
            
            fp = fopen(path_buf, "r");
            if (fp == NULL) {
                ERROR("Failed to read config file %s", entry->d_name)
                continue;
            }

            while (getline(&conf_buf, &size, fp) != -1) {
                conf_buf[strcspn(conf_buf, "\n")] = 0;
                if (conf_buf[0] != '#' && strlen(conf_buf) > 0) {
                    WARNING("Module '%s' is persisted via config file [%s]", conf_buf, path_buf)
                    found++;
                }
            }

            fclose(fp);
            memset(path_buf, 0, PATH_MAX);
        }
    }

    closedir(dirp);
    free(conf_buf);
    return found;
}