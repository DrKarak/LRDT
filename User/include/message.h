#include <stdio.h>
#include "scan.h"

/*
    Macros for pretty output messages
*/

#define TEXT(msg, ...) printf("\033[0;37m"msg"\033[0m\n", ##__VA_ARGS__);

#define TITLE(msg, ...) printf("\033[1;37m"msg"\033[0m\n", ##__VA_ARGS__);

#define INFO(msg, ...) printf("[\033[0;35mINFO\033[0m] "msg"\n", ##__VA_ARGS__);

#define DEBUG(msg, ...) printf("[\033[1;96mDEBUG\033[0m] "msg"\n", ##__VA_ARGS__);

#define OK(msg, ...) printf("[\033[0;32mOK\033[0m] "msg"\n", ##__VA_ARGS__);

#define FATAL(msg, ...) {\
    printf("[\033[41mFATAL\033[0m] "msg"\n", ##__VA_ARGS__);\
    error++;\
}

#define ERROR(msg, ...) {\
    printf("[\033[0;31mERROR\033[0m] "msg"\n", ##__VA_ARGS__);\
    error++;\
}

#define WARNING(msg, ...) {\
    printf("[\033[0;93mWARNING\033[0m] "msg"\n", ##__VA_ARGS__);\
    warning++;\
}

#define ALERT(msg, ...) {\
    printf("[\033[1;31mALERT\033[0m] "msg"\n", ##__VA_ARGS__);\
    alert++;\
}

#define DIV printf("================\n");