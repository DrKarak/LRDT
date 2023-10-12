#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include "scan.h"
#include "message.h"
#include "hidden_files.h"

/*
    Scan for hidden directories (adapted from chkrootkit)

    @param path filepath
    @param rec  recursive
    @return number of hiddendirectories
*/
int hidden_hlink_scan(char* path, int rec) {
    char path_buf[PATH_MAX];
    struct dirent* entry;
    struct stat dstats;
    DIR* dirp;

    dirp = opendir(path);
    if (dirp == NULL) {
        ERROR("Failed to open directory: %s", path)
        return 0;
    }

    int count_dir, found, diff;
    count_dir = found = 0;

    if (stat(path, &dstats) != 0) {
        ERROR("Failed to get stats for directory: %s", path)
        return 0;
    }

    while ((entry = readdir(dirp)) != 0) {
        if (entry->d_type == DT_DIR) {
            if (rec != 0 
                & strcmp(".", entry->d_name) != 0 
                & strcmp("..", entry->d_name) != 0) {

                snprintf(path_buf, PATH_MAX, "%s/%s", path, entry->d_name);
                found += hidden_hlink_scan(path_buf, rec);
            }
            count_dir++;
        }
    }
    diff = dstats.st_nlink - count_dir;
    found += diff;

    if (diff > 0) {
        ALERT("%s contains %i hidden dir(s)", path, diff)
    } else if (found < 0) {
        found = 0;
    }

    closedir(dirp);
    return found;
}