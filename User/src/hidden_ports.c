#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include "scan.h"
#include "message.h"
#include "hidden_ports.h"

/*
    Check if port is visible in netstat or ss

    @param port     port
    @param protocol t4 | t6 | u4 | u6
    @return non-zero value if true
*/
int port_is_visible(int port, char* protocol) {
    FILE *fp;
    char cmd[32], proto[32], state[32], local[64], peer[64], p[7];
    char *off;
    int recv, send;

    snprintf(p, 7, "%i", port);

    snprintf(cmd, 32, "ss -%san", protocol);

    fp = popen(cmd, "r");
    if (fp == NULL) {
        ERROR("Failed to check visibility of port %i in ss", port)
    }

    while (fscanf(fp, "%32s %i %i %64s %64s", state, &recv, &send, local, peer) > 0) {
        off = strrchr(local, ':');
        if (off == NULL) continue;
        if (strcmp(off + 1, p) == 0) {
            pclose(fp);
            return 1;
        }
    }

    pclose(fp);

    snprintf(cmd, 32, "netstat -%san", protocol);

    fp = popen(cmd, "r");
    if (fp == NULL) {
        ERROR("Failed to check visibility of port %i in netstat", port)
    }

    while (fscanf(fp, "%32s %i %i %64s %64s %32s", proto, &recv, &send, local, peer, state) > 0) {
        off = strrchr(local, ':');
        if (off == NULL) continue;
        if (strcmp(off + 1, p) == 0) {
            pclose(fp);
            return 1;
        }
    }

    pclose(fp);
    return 0;
}

/*
    Check if TCPv4 port is visible

    @param port port
    @return non-zero value if true
*/
int tcp4_port_is_hidden(int port) {
    int sock, hidden = 0;
    struct sockaddr_in addr;
    errno = 0;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0) {
        ERROR("Failed to create socket for tcp4 port %i", port)
    } else {
        if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            if (errno == EADDRINUSE) {
                if (port_is_visible(port, "t4") == 0) {
                    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                        if (errno == EADDRINUSE) {
                            hidden = 1;
                        }
                    } else {
                        ERROR("Failed to bind to socket for tcp4 port %i", port)
                    }
                }
            }
        } else {
            listen(sock, 1);
            if (errno == EADDRINUSE) {
                if (port_is_visible(port, "t4") == 0) {
                    listen(sock, 1);
                    if (errno == EADDRINUSE) {
                        hidden = 1;
                    }
                }
            }
        }
    }

    close(sock);
    return hidden;
}

/*
    Check if TCPv6 port is visible

    @param port port
    @return non-zero value if true
*/
int tcp6_port_is_hidden(int port) {
    int sock, hidden = 0, opt = 1;
    struct sockaddr_in6 addr;
    errno = 0;

    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port);

    sock = socket(AF_INET6, SOCK_STREAM, 0);
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&opt, sizeof(opt));

    if (sock < 0) {
        ERROR("Failed to create socket for tcp6 port %i", port)
    } else {
        if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            if (errno == EADDRINUSE) {
                if (port_is_visible(port, "t6") == 0) {
                    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                        if (errno == EADDRINUSE) {
                            hidden = 1;
                        }
                    } else {
                        ERROR("Failed to bind to socket for tcp6 port %i", port)
                    }
                }
            }
        } else {
            listen(sock, 1);
            if (errno == EADDRINUSE) {
                if (port_is_visible(port, "t6") == 0) {
                    listen(sock, 1);
                    if (errno == EADDRINUSE) {
                        hidden = 1;
                    }
                }
            }
        }
    }

    close(sock);
    return hidden;
}

/*
    Check if UDPv4 port is visible

    @param port port
    @return non-zero value if true
*/
int udp4_port_is_hidden(int port) {
    int sock, hidden = 0;
    struct sockaddr_in addr;
    errno = 0;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        ERROR("Failed to create socket for udp4 port %i", port)
    } else {
        if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            if (errno == EADDRINUSE) {
                if (port_is_visible(port, "u4") == 0) {
                    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
                        if (errno == EADDRINUSE) {
                            hidden = 1;
                        }
                    }
                }
            } else {
                ERROR("Failed to bind to socket for udp4 port %i", port)
            }
        }
    }

    close(sock);
    return hidden;
}

/*
    Check if UDPv6 port is visible

    @param port port
    @return non-zero value if true
*/
int udp6_port_is_hidden(int port) {
    int sock, hidden = 0, opt = 1;
    struct sockaddr_in6 addr;
    errno = 0;

    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port);

    sock = socket(AF_INET6, SOCK_DGRAM, 0);
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&opt, sizeof(opt));

    if (sock < 0) {
        ERROR("Failed to create socket for udp6 port %i", port)
    } else {
        if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            if (errno == EADDRINUSE) {
                if (port_is_visible(port, "u6") == 0) {
                    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
                        if (errno == EADDRINUSE) {
                            hidden = 1;
                        }
                    }
                }
            } else {
                ERROR("Failed to bind to socket for udp6 port %i", port)
            }
        }
    }

    close(sock);
    return hidden;
}

/*
    Scan for ports hiding from netstat and ss (adapted from Unhide/OSSEC)

    @return number of hidden ports
*/
int hidden_ports_scan(void) {
    int i, found = 0;

    for (i = 1; i <= 65535; i++) {
        if (tcp4_port_is_hidden(i) > 0) {
            WARNING("TCPv4 port %i is hidden from ss/netstat", i)
            found++;
        }
        if (tcp6_port_is_hidden(i) > 0) {
            WARNING("TCPv6 port %i is hidden from ss/netstat", i)
            found++;
        }
        if (udp4_port_is_hidden(i) > 0) {
            WARNING("UDPv4 port %i is hidden from ss/netstat", i)
            found++;
        }
        if (udp6_port_is_hidden(i) > 0) {
            WARNING("UDPv6 port %i is hidden from ss/netstat", i)
            found++;
        }
    }

    return found;
}
