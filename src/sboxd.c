#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/uio.h>
#include <pthread.h>
#include <linux/limits.h>
#include <linux/un.h>
#include <seccomp.h>

#include <sbox.h>
#include <util.h>
int verbose;

int caught_signal;


#define MAX_PROCS     128
#define MAX_PROC_FDS  128
#define MAX_PROC_MEMS 128


struct sboxd_mem {
        uintptr_t start, end;
};

/* XXX: ughhh,, global vars. ultra tekitou work */
struct sboxd_proc {
        pid_t pid;

        /* cache of checked fds */
        fd_set fds;             /* all fds used in this proc */
        fd_set secure_fds;      /* secure fds in the fds */
        fd_set insecure_fds;    /* insecure fds in the fds*/

        struct sboxd_mem *mems[MAX_PROC_MEMS];
};

struct sboxd_proc procs[MAX_PROCS];

struct sboxd_proc *sboxd_proc_recycle(struct sboxd_proc *p)
{
        int n;
        for (n = 0; n < MAX_PROC_MEMS; n++) {
                if (p->mems[n]) {
                        free(p->mems[n]);
                }
        }
        return p;
}

struct sboxd_proc *sboxd_proc_alloc(pid_t pid)
{
        struct sboxd_proc *p = NULL;
        struct stat buf;
        char path[PATH_MAX];
        int n;

        /* XXX: need lock? */

        for (n = 0; n < MAX_PROCS; n++) {
                if (procs[n].pid == 0) {
                        p = &procs[n];
                        break;
                }
                        
                memset(path, 0, sizeof(path));
                snprintf(path, sizeof(path), "/proc/%d", procs[n].pid);
                if (stat(path, &buf) != 0) {
                        /* this pid process doesn't exist. recycle */
                        p = sboxd_proc_recycle(&procs[n]);
                        break;
                }
        }

        if (!p) {
                pr_err("no available proc slot!\n");
                return NULL;
        }

        memset(p, 0, sizeof(*p));
        p->pid = pid;
        return p;
}

struct sboxd_proc *sboxd_proc_find(pid_t pid)
{
        int n;
        for (n = 0; n < MAX_PROCS; n++) {
                if (procs[n].pid == pid)
                        return &procs[n];
        }

        return sboxd_proc_alloc(pid);
}


int sboxd_proc_add_mem(struct sboxd_proc *p, uintptr_t start, size_t len)
{
        /* XXX: Ultra Tekitou Work */

        struct sboxd_mem *m;
        int n;

        m = malloc(sizeof(*m));
        memset(m, 0, sizeof(*m));
        m->start = start;
        m->end = start + len;

         for (n = 0; n < MAX_PROC_MEMS; n++) {
                if (p->mems[n] == NULL) {
                        p->mems[n] = m;
                        return 0;
                }
        }

        pr_err("no space to store mem region for pid %d\n", p->pid);
        return -1;
}


int sboxd_proc_check_mem(struct sboxd_proc *p, uintptr_t start, size_t len)
{
        uintptr_t end = start + len;
        struct sboxd_mem *m;
        int n;

        for (n = 0; n < MAX_PROC_MEMS; n++) {
                m = p->mems[n];
                if (!m)
                        continue;

                /* check are regions overlapped */
                if ((start <= m->start && m->start <= end) ||
                    (start <= m->end && m->end <= end))
                        return 1;
        }

        return 0;
}

static int seccomp(unsigned int op, unsigned int flags, void *args)
{
        errno = 0;
        return syscall(__NR_seccomp, op, flags, args);
}


int unix_serv_sock(void)
{
        struct sockaddr_un saddr_un;
        int sock;
        
        pr_v3("create unix server socket on %s\n", SBOXD_UNIX_DOMAIN);

        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
                pr_err("failed to create unix socket: %s\n", strerror(errno));
                return -1;
        }

        memset(&saddr_un, 0, sizeof(saddr_un));
        saddr_un.sun_family = AF_UNIX;
        strncpy(saddr_un.sun_path, SBOXD_UNIX_DOMAIN, UNIX_PATH_MAX);

        if (bind(sock, (struct sockaddr *)&saddr_un, sizeof(saddr_un)) < 0) {
                pr_err("failed to bind unix socket on %s: %s\n",
                       SBOXD_UNIX_DOMAIN, strerror(errno));
                close(sock);
                return -1;
        }

        if (listen(sock, 1) != 0) {
                pr_err("failed to listen unix socket: %s\n",
                       strerror(errno));
                close(sock);
                return -1;
        }

        if (chmod(SBOXD_UNIX_DOMAIN,
                  (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP |
                   S_IROTH | S_IWOTH)) < 0) {
                pr_err("failed to set permission of %s: %s\n",
                       SBOXD_UNIX_DOMAIN, strerror(errno));
                close(sock);
                return -1;
        }


        return sock;
}



ssize_t process_vm_read(pid_t pid, uintptr_t dest, void *buf, size_t count)
{
        struct iovec local, remote;

        local.iov_base = buf;
        local.iov_len = count;
        remote.iov_base = (void *)dest;
        remote.iov_len = count;

        return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

ssize_t process_vm_write(pid_t pid, uintptr_t dest, void *buf, size_t count)
{
        struct iovec local, remote;

        local.iov_base = buf;
        local.iov_len = count;
        remote.iov_base = (void *)dest;
        remote.iov_len = count;

        return process_vm_writev(pid, &local, 1, &remote, 1, 0);
}

int sboxd_compromise_buf(struct sboxd_proc *p, uintptr_t dest, size_t count)
{
        char buf[count];
        int n;

        if (process_vm_read(p->pid, dest, buf, count) < 0) {
                pr_err("process_vm_read: %s\n", strerror(errno));
                return -1;
        }

        for (n = 0; n < count; n++) {
                if (buf[n] != '\n' && rand() & 0x1) {
                        buf[n] = 'X';
                }
        }

        if (process_vm_write(p->pid, dest, buf, count) < 0) {
                pr_err("process_vm_write: %s\n", strerror(errno));
                return -1;
        }

        return 0;
}

int sboxd_is_secure_fd(struct sboxd_proc *p, int fd)
{
        /* return value 1 means fd is opened on file path contains
         *  "secure", 0 means not secure, and -1 is error;
         */
        char proc_path[PATH_MAX], file_path[PATH_MAX];

        /* check cache */
        if (FD_ISSET(fd, &p->secure_fds))
                return 1;
        else if (FD_ISSET(fd, &p->insecure_fds))
                return 0;

        /* not hit in the cache. check /proc/X/fd/FD*/
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd/%d", p->pid, fd);
        memset(file_path, 0, sizeof(file_path));
        if (readlink(proc_path, file_path, sizeof(file_path)) < 0) {
                pr_err("readlink failed %s: %s\n", proc_path, strerror(errno));
                return -1;
        }
        
        pr_v3("check proc %s -> %s\n", proc_path, file_path);

        if (strstr(file_path, "secure")) {
                FD_SET(fd, &p->secure_fds);
                return 1;
        }

        /* insecure fd */
        FD_SET(fd, &p->insecure_fds);
        return 0;
}

void sboxd_handle_read(struct sboxd_proc *t, struct seccomp_notif *req)
{
        int ret, fd;
        __u64 *args;
        
        args = req->data.args;
        fd = args[0];


        ret = sboxd_is_secure_fd(t, fd);
        if (ret < -1)
                return;

        pr_v3("pid=%d read fd=%d 0x%llx-0x%llx\n", req->pid,
              fd, args[1], args[1] + args[2]);

        if (ret) {
                /* fd is secure. mark this buf region has secure content */
                pr_v3("pid=%d read from secure fd %d\n", req->pid, fd);
                if(sboxd_proc_add_mem(t, args[1], args[2]) < 0)
                        return; /* XXX: should stop the process */
        } else {
                pr_v3("read from insecure fd %d\n", fd);
        }
}

void sboxd_handle_write(struct sboxd_proc *t, struct seccomp_notif *req)
{
        int ret, fd;
        __u64 *args;

        args = req->data.args;
        fd = args[0];

        ret = sboxd_is_secure_fd(t, fd);
        if (ret < -1)
                return;

        pr_v3("pid=%d write fd=%d 0x%llx-0x%llx\n", req->pid,
              fd, args[1], args[1] + args[2]);

        if (ret) {
                pr_v3("write to secure fd %d, pass\n", fd);
                return;
        }

        /* write to unsecure fd. check whether buf has secure content */
        ret = sboxd_proc_check_mem(t, args[1], args[2]);
        if (ret) {
                pr_warn("pid=%d write secure buf to insecure fd %d !!!!\n",
                        req->pid, fd);
                if (sboxd_compromise_buf(t, args[1], args[2]) < 0)
                        pr_err("failed to compromise output\n");
        } else {
                pr_v3("write insecure buf to insecure fd %d\n", fd);
        }
}

void sboxd_handle_close(struct sboxd_proc *p, struct seccomp_notif *req)
{
        int fd = req->data.args[0];
 
        if (fd >= 0) {
                pr_v3("close fd %d\n", fd);
                FD_CLR(fd, &p->secure_fds);
                FD_CLR(fd, &p->insecure_fds);
        }
}

void sboxd_handle_req(int notif_fd, struct seccomp_notif *req,
                      struct seccomp_notif_resp *rep)
{
        struct sboxd_proc *p;
        char *syscall;
        int ret;

        syscall = seccomp_syscall_resolve_num_arch(req->data.arch,
                                                   req->data.nr);
        if (!syscall) {
                pr_warn("failed to resolve syscall syscall for %d",
                        req->data.nr);
                goto out;
        }

        pr_v2("syscall %s\n", syscall);
        p = sboxd_proc_find(req->pid);
        if (!p) {
                pr_err("abort\n");
                goto out;
        }

        if (strcmp(syscall, "read") == 0) {
                sboxd_handle_read(p, req);
        } else if (strcmp(syscall, "write") == 0) {
                sboxd_handle_write(p, req);
        } else if (strcmp(syscall, "close") == 0) {
                sboxd_handle_close(p, req);
        }

out:
        rep->id = req->id;
        rep->val = 0;
        rep->error = 0;
        rep->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

        pr_v3("send notify response\n");
        ret = seccomp_notify_respond(notif_fd, rep);
        if (ret < 0) {
                pr_warn("seccomp_notify_respond failed: %s\n",
                         strerror(ret * -1));
        }
}

void *sboxd_thread(void *arg)
{
        int notif_fd = *((int *)arg);
        struct seccomp_notif_resp *rep = NULL;
        struct seccomp_notif *req = NULL;
        struct seccomp_notif_sizes sizes;
        struct pollfd x[1];
        char prefix[64];
        int ret;

        snprintf(prefix, sizeof(prefix), "notif_fd %d", notif_fd);

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

        x[0].fd = notif_fd;
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

                ret = seccomp_notify_receive(notif_fd, req);
                if (ret < 0) {
                        pr_err("%s: seccomp_notify_receive: %s, errno %s\n",
                               prefix, strerror(ret * -1),
                               strerror(errno));
                        continue;
                }
                
                if (seccomp_notify_id_valid(notif_fd, req->id) != 0) {
                        pr_warn("%s: invalid notify id. process exited?\n",
                                prefix);
                        continue;
                }

                /* handle notif req */
                sboxd_handle_req(notif_fd, req, rep);
        }
        
        pr_v1("clean up sboxd_thread for notif_fd %d\n", notif_fd);
              
        seccomp_notify_free(req, rep);
err_out:
        close(notif_fd);
        pr_v1("exit sboxd thread for notif_fd %d\n", notif_fd);
        free(arg);
        return NULL;
}

void sboxd_spawn(int notif_fd)
{
        pthread_t tid;
        int *fd;

        pr_v1("spawn thread for notif_fd %d\n", notif_fd);

        fd = malloc(sizeof(int));
        *fd = notif_fd;

        if (pthread_create(&tid, NULL, sboxd_thread, fd) < 0)
                pr_err("failed to spawn sboxd thread: %s\n", strerror(errno));
}

int sboxd_recv_req(int sock)
{
        char buf[CMSG_SPACE(sizeof(int))], c;
        struct msghdr msg = {};
        struct cmsghdr *cmsg;
        struct iovec iov[1];
        
        iov[0].iov_base = &c;
        iov[0].iov_len = 1;
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        msg.msg_control = buf;
        msg.msg_controllen = sizeof(buf);

        if (recvmsg(sock, &msg, 0) < 0) {
                pr_err("recvmsg from unix socket failed: %s\n",
                       strerror(errno));
                return -1;
        }

        cmsg = CMSG_FIRSTHDR(&msg);
        return *((int *)CMSG_DATA(cmsg));
}

int sboxd(int un_sock)
{
        struct pollfd x = { .fd = un_sock, .events = POLLIN };
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

                notif_fd = sboxd_recv_req(fd);
                if (notif_fd < 0) {
                        continue;
                }

                sboxd_spawn(notif_fd);
                close(fd);
        }

        close(un_sock);
        unlink(SBOXD_UNIX_DOMAIN);

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
               "  sboxd: MonBan daemon, watch and catch syscalls\n"
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

        srand(time(NULL));
        memset(procs, 0, sizeof(procs));
        
        if (signal(SIGINT, sig_handler) == SIG_ERR) {
                pr_err("cannot set signal handler for SIGINT: %s\n",
                       strerror(errno));
                return -1;
        }

        un_sock = unix_serv_sock();
        if (un_sock < 0)
                return -1;

        return sboxd(un_sock);
}
