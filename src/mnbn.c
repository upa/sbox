#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <seccomp.h>

#include <mnbn.h>
#include <util.h>
int verbose = 0;


int unix_client_sock(void)
{
        struct sockaddr_un un;
        int sock;

        pr_v3("create unix client socket on %s\n", MNBND_UNIX_DOMAIN);

        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
                pr_err("failled to create unix socket: %s\n", strerror(errno));
                return -1;
        }

        memset(&un, 0, sizeof(un));
        un.sun_family = AF_UNIX;
        strncpy(un.sun_path, MNBND_UNIX_DOMAIN, UNIX_PATH_MAX);
        if (connect(sock, (struct sockaddr *)&un, sizeof(un)) < 0) {
                pr_err("failed to connect to %s: %s\n",
                       MNBND_UNIX_DOMAIN, strerror(errno));
                close(sock);
                return -1;
        }

        return sock;
}

int mnbn_send_req(int sock, int notif_fd)
{
        char buf[CMSG_SPACE(sizeof(int))];
        struct msghdr msg = {};
        struct cmsghdr *cmsg;
        struct iovec iov[1];
        struct mnbn_target_req req;

        req.pid = getpid();
        iov[0].iov_base = &req;
        iov[0].iov_len = sizeof(req);
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        msg.msg_control = buf;
        msg.msg_controllen = sizeof(buf);
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        *((int *)CMSG_DATA(cmsg)) = notif_fd;

        if (sendmsg(sock, &msg, 0) < 0) {
                return -1;
        }
        
        return 0;
}

int mnbn_seccomp_init(void)
{
        scmp_filter_ctx ctx = NULL;
        int ret, notif_fd;

        pr_v1("initialize seccomp\n");

        ctx = seccomp_init(SCMP_ACT_ALLOW);
        if (!ctx) {
                pr_err("failed to seccomp_init: %s\n", strerror(errno));
                return -1;
        }

        if (seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1) != 0) {
                 pr_err("failed to set SCMP_FLTATR_CTL_TSYNC=1: %s\n",
                       strerror(errno));
                goto err_release_out;
        }

#define rule_add(syscall)                                               \
        do {                                                            \
                pr_v2("add rule for " #syscall "\n");                   \
                ret = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY,            \
                                       SCMP_SYS(syscall), 0, NULL);      \
                if (ret < 0) {                                          \
                        pr_err("failed to add rule for " #syscall ": %s\n", \
                               strerror(errno));                        \
                }                                                       \
        } while (0) 

        rule_add(open);
        rule_add(openat);
        rule_add(write);
        rule_add(writev);
        rule_add(read);
        rule_add(readv);
        rule_add(close);

        pr_v2("load seccomp\n");
        if (seccomp_load(ctx) != 0) {
                pr_err("failed to seccomp_load: %s\n", strerror(errno));
                goto err_release_out;
        }

        notif_fd = seccomp_notify_fd(ctx);
        if (notif_fd < 0) {
                goto err_release_out;
        }
        
         return notif_fd;


err_release_out:
        seccomp_release(ctx);
        return -1;
}

void usage(void)
{
        printf("mnbn COMMAND ARGS...\n");
}

int main(int argc, char **argv)
{
        int sock, notif_fd;

        if (argc < 2) {
                usage();
                return -1;
        }

        sock = unix_client_sock();
        if (sock < 0)
                return -1;

        notif_fd = mnbn_seccomp_init();
        if (notif_fd < 0)
                return -1;

        if (mnbn_send_req(sock, notif_fd) < 0)
                return -1;
        close(sock);

        argc--;
        argv++;
        return execvp(argv[0], argv);
}
