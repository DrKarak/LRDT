#define _GNU_SOURCE
#define _XOPEN_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sched.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <ctype.h>
#include <time.h>
#include <wait.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/resource.h>
#include "scan.h"
#include "message.h"
#include "hidden_ports.h"

/*
    Get maximum PID or use default (32768)

    @return maximum PID
*/
int max_pid(void) {
    FILE *fp;
    int m_pid;

    fp = fopen("/proc/sys/kernel/pid_max", "r");
    if (fp == NULL) {
        ERROR("Unable to obtain max pid. Using default: 32768")
        return 32768;
    }

    if (fscanf(fp, "%i", &m_pid) < 0) {
        ERROR("Unable to obtain max pid. Using default: 32768")
        return 32768;
    }

    fclose(fp);
    return m_pid;
}

/*
    Check if PID is in ps commandline output

    @param cmd command to execute
    @param p   PID
    @return non-zero value if true
*/
int pid_in_ps_cmd(char *cmd, char *p) {
    FILE *fp;
    char buf[32];
    char *off;

    fp = popen(cmd, "r");
    if (fp == NULL) {
        ERROR("Failed to check visibility of pid %s in ps", p)
    }

    while (fgets(buf, 32, fp)) {
        off = strrchr(buf, ' ');
        if (off != NULL) {
            buf[strcspn(buf, "\n")] = 0;
            if (strcmp(p, off + 1) == 0) {
                pclose(fp);
                return 1;
            }
        }
    }

    pclose(fp);
    return 0;
}

/*
    Check if PID is visible

    @param pid PID
    @return non-zero value if true
*/
int pid_is_visible(int pid) {
    FILE *fp;
    char cmd[48], p[7], buf[32];

    snprintf(p, 7, "%i", pid);

    snprintf(cmd, 48, "ps --no-heading -p %i -o pid", pid);
    if (pid_in_ps_cmd(cmd, p)) return 1;

    snprintf(cmd, 48, "ps --no-heading -eL -o lwp");
    if (pid_in_ps_cmd(cmd, p)) return 1;

    return 0;
}

/*
    Try to get kernel arguments and print alert

    @param pid PID
*/
void print_process_alert(int pid) {
    FILE *fp;
    char buf[512], path_buf[40];
    buf[0] = '?';

    snprintf(path_buf, 40, "/proc/%i/cmdline", pid);

    fp = fopen(path_buf, "r");
    if (fp != NULL) {
        fgets(buf, 512, fp);
    }

    ALERT("Process %i is hiding from ps [%s]", pid, buf)
}

/*
    Scan for processes hiding from ps (adapted from Unhide/OSSEC)

    @return number of hidden processes
*/
int hidden_procs_scan(void) {
    DIR *dirp;
    cpu_set_t m;
    struct sched_param p;
    struct timespec t;
    struct stat buf;
    int i, self, m_pid, vis, start, finish;
    char path_buf[32];
    int found = 0;
    char cwd[PATH_MAX];

    m_pid = max_pid();
    self = getpid();
    getcwd(cwd, PATH_MAX);

    for (i = 1; i <= m_pid; i++) {
        if (i == self) continue;

        vis = start = finish = 0;

        errno = 0;
        kill(i, 0);
        if (errno == 0) start = 1;

        snprintf(path_buf, 32, "/proc/%i", i);

        if (stat(path_buf, &buf) == 0) vis++;

        if (chdir(path_buf) == 0) {
            chdir(cwd);
            vis++;
        }

        if ((dirp = opendir(path_buf)) != NULL) {
            vis++;
            closedir(dirp);
        }

        errno = 0;
        getpriority(PRIO_PROCESS, i);
        if (errno == 0) vis++;

        errno = 0;
        getpgid(i);
        if (errno == 0) vis++;

        errno = 0;
        getsid(i);
        if (errno == 0) vis++;

        errno = 0;
        sched_getaffinity(i, sizeof(cpu_set_t), &m);
        if (errno == 0) vis++;

        errno = 0;
        sched_getparam(i, &p);
        if (errno == 0) vis++;

        errno = 0;
        sched_getscheduler(i);
        if (errno == 0) vis++;

        errno = 0;
        sched_rr_get_interval(i, &t);
        if (errno == 0) vis++;

        if (start != 0 || vis != 0) {
            if (pid_is_visible(i) == 0) {
                errno = 0;
                kill(i, 0);
                if (errno == 0) finish = 1;
                if (start == finish && vis > 0) {
                    print_process_alert(i);
                    found++;
                }
            }
        }
    }

    return found;
}