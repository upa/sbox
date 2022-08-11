#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <linux/un.h>
#include <pthread.h>
#include <seccomp.h>

#include <mnbn.h>

#include <util.h>
int verbose;

int caught_signal;


#define MAX_TARGET_FDS  128
#define MAX_TARGET_MEMS 128


struct mnbnd_spoofed_fd {
        int real_fd;    /* real fd in the target */
        int pair_fd;    /* socket pair. a pair is passed to target*/
};

struct mnbnd_mem {
        uintptr_t start, end;
};

struct mnbnd_target {
        pid_t pid;
        int notif_fd;         /* seccomp notify fd */

        struct mnbnd_spoofed_fd *sfds[MAX_TARGET_FDS];
        struct mnbnd_mem *mems[MAX_TARGET_MEMS];
};

static int seccomp(unsigned int op, unsigned int flags, void *args)
{
        errno = 0;
        return syscall(__NR_seccomp, op, flags, args);
}


int unix_serv_sock(void)
{
        struct sockaddr_un saddr_un;
        int sock;
        
        pr_v3("create unix server socket on %s\n", MNBND_UNIX_DOMAIN);

        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
                pr_err("failed to create unix socket: %s\n", strerror(errno));
                return -1;
        }

        memset(&saddr_un, 0, sizeof(saddr_un));
        saddr_un.sun_family = AF_UNIX;
        strncpy(saddr_un.sun_path, MNBND_UNIX_DOMAIN, UNIX_PATH_MAX);

        if (bind(sock, (struct sockaddr *)&saddr_un, sizeof(saddr_un)) < 0) {
                pr_err("failed to bind unix socket on %s: %s\n",
                       MNBND_UNIX_DOMAIN, strerror(errno));
                close(sock);
                return -1;
        }

        if (listen(sock, 1) != 0) {
                pr_err("failed to listen unix socket: %s\n",
                       strerror(errno));
                close(sock);
                return -1;
        }

        return sock;
}

void mnbnd_handle_req(struct mnbnd_target *t, struct seccomp_notif *req,
                      struct seccomp_notif_resp *rep)
{
        rep->id = req->id;
        rep->val = 0;
        rep->error = 0;
        rep->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
}

void *mnbnd_thread(void *arg)
{
        struct mnbnd_target *t = arg;
        struct seccomp_notif_resp *rep = NULL;
        struct seccomp_notif *req = NULL;
        struct seccomp_notif_sizes sizes;
        char prefix[64], *name;
        struct pollfd x[1];
        int ret;

        snprintf(prefix, sizeof(prefix), "pid %d notif_fd %d",
                 t->pid, t->notif_fd);

        if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0) {
                pr_err("%s: failed to get netif sizes: %s\n",
                       prefix, strerror(errno));
                goto err_out;
        }

        ret = seccomp_notify_alloc(&req, &rep);
        if (ret < 0) {
                pr_err("%s: failed to seccomp_notify_alloc: %s\n",
                       prefix, strerror(ret * -1));
                goto err_out;
        }

        pr_v3("req=%p rep=%p\n", req, rep);

        x[0].fd = t->notif_fd;
        x[0].events = POLLIN;

        while (1) {
                if (caught_signal)
                        break;

                if (poll(x, 1, -1) < 0) {
                        if (errno != EINTR) {
                                pr_err("%s: poll failed: %s\n",
                                       prefix, strerror(errno));
                        }
                        break;
                }
                
                if (x[0].revents & POLLHUP) {
                        pr_v3("poll hup\n");
                        break;
                }

                if (!(x[0].revents & POLLIN))
                        continue;

                pr_v3("%s: seccomp notify in!\n", prefix);
                memset(req, 0, sizes.seccomp_notif);
                memset(rep, 0, sizes.seccomp_notif_resp);

                pr_v3("hoge\n");
                ret = seccomp_notify_receive(t->notif_fd, req);
                if (ret < 0) {
                        pr_err("%s: seccomp_notify_receive failed: %s\n",
                               prefix, strerror(ret * -1));
                        break;
                }
                
                pr_v3("%s: id %llx pid %d flags %u\n",
                      prefix, req->id, req->pid, req->flags);
                if (seccomp_notify_id_valid(t->notif_fd, req->id) != 0) {
                        pr_warn("%s: invalid notify id. process exited?\n",
                                prefix);
                        break;
                }

                name = seccomp_syscall_resolve_num_arch(req->data.arch,
                                                        req->data.nr);
                if (!name) {
                        pr_warn("%s: failed to resolve syscall name for %d",
                                prefix, req->data.nr);
                } else {
                        pr_info("%s: syscall %s\n", prefix, name);
                }

                /* handle notif req */
                mnbnd_handle_req(t, req, rep);

                pr_v3("%s: send notify response\n", prefix);
                ret = seccomp_notify_respond(t->notif_fd, rep);
                if (ret < 0) {
                        pr_warn("%s: seccomp_notify_respond failed: %s\n",
                                prefix, strerror(ret * -1));
                }

        }
        
        pr_v1("clean up mnbnd_thread for pid %u notif_fd %d\n",
              t->pid, t->notif_fd);
        seccomp_notify_free(req, rep);
err_out:
        close(t->notif_fd);
        pr_v1("exit mnbnd thread for pid %u notif_fd %d\n",
              t->pid, t->notif_fd);
        free(t);
        return NULL;
}

void mnbnd_spawn(int notif_fd, struct mnbn_target_req *req)
{
        struct mnbnd_target *t;
        pthread_t tid;

        pr_v1("spawn thread for pid %d notif_fd %d\n", req->pid, notif_fd);

        t = (struct mnbnd_target *)malloc(sizeof(*t));
        memset(t, 0, sizeof(*t));

        t->pid = req->pid;
        t->notif_fd = notif_fd;

        if (pthread_create(&tid, NULL, mnbnd_thread, t) < 0)
                pr_err("failed to spawn mnbnd thread: %s\n", strerror(errno));
}

/* return notify fd or -1 when faild, and fill *req */
int mnbnd_recv_req(int sock, struct mnbn_target_req *req)
{
        char buf[CMSG_SPACE(sizeof(int))];
        struct msghdr msg = {};
        struct cmsghdr *cmsg;
        struct iovec iov[1];
        
        iov[0].iov_base = req;
        iov[0].iov_len = sizeof(*req);
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        msg.msg_control = buf;
        msg.msg_controllen = sizeof(buf);

        if (recvmsg(sock, &msg, 0) < 0) {
                pr_err("recvmsg from unix socket failed: %s\n",
                       strerror(errno));
                return -1;
        }

        pr_v2("request received from pid %d\n", req->pid);

        cmsg = CMSG_FIRSTHDR(&msg);
        return *((int *)CMSG_DATA(cmsg));
}

int mnbnd(int un_sock)
{
        struct pollfd x = { .fd = un_sock, .events = POLLIN };
        struct mnbn_target_req req;
        struct sockaddr_storage ss;
        int fd, notif_fd, ret = 0;
        socklen_t addrlen;

        pr_v1("enter loop for waiting request\n");
        while (1) {
                if (caught_signal)
                        break;

                if (poll(&x, 1, 1000) < 0) {
                        if (errno != EINTR) {
                                pr_err("poll failed: %s\n", strerror(errno));
                                ret = -1;
                        }
                        break;
                }

                if (!x.revents & POLLIN)
                        continue;

                fd = accept(un_sock, (struct sockaddr *)&ss, &addrlen);
                if (fd < 0) {
                        pr_err("accept failed: %s\n", strerror(errno));
                        ret = -1;
                        break;
                }

                notif_fd = mnbnd_recv_req(fd, &req);
                if (notif_fd < 0) {
                        continue;
                }

                mnbnd_spawn(notif_fd, &req);
                close(fd);
        }

        close(un_sock);
        unlink(MNBND_UNIX_DOMAIN);

        return ret;
}

void sig_handler(int sig)
{
        if (sig == SIGINT)
                caught_signal = 1;
 }

void usage(void)
{
        printf("\n"
               "  mnbnd: MonBan daemon, watch and catch syscalls\n"
               "\n"
               "  usage:\n"
               "        -v        increment verbose level\n"
               "\n"
               "        -h        print this help\n"
               "\n"
                );
                
}

int main(int argc, char **argv)
{
        int ch, un_sock;

        while ((ch = getopt(argc, argv, "vh")) != -1) {
                switch (ch) {
                case 'v':
                        verbose++;
                        break;
                case 'h':
                default:
                        usage();
                        return -1;
                }
        }
        
        if (signal(SIGINT, sig_handler) == SIG_ERR) {
                pr_err("cannot set signal handler for SIGINT: %s\n",
                       strerror(errno));
                return -1;
        }

        un_sock = unix_serv_sock();
        if (un_sock < 0)
                return -1;

        return mnbnd(un_sock);
}
