#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHILD_UID   1000
#define CHILD_GID   1000
#define PATH_BUFLEN 4096

static const char *BLOCKED_PATHS[] = {
    "/flag",
    "/root",
    "/etc/shadow",
    "/etc/gshadow",
    "/proc/self/mem",
    "/proc/self/exe",
    "/proc/self/root",
    NULL
};

static int is_path_blocked(const char *path) {
    for (int i = 0; BLOCKED_PATHS[i] != NULL; i++) {
        if (strncmp(path, BLOCKED_PATHS[i], strlen(BLOCKED_PATHS[i])) == 0)
            return 1;
    }
    return 0;
}

static int read_tracee_string(pid_t pid, uint64_t remote_addr,
                              char *buf, size_t len) {
    struct iovec local  = { .iov_base = buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void *)(uintptr_t)remote_addr,
                            .iov_len  = len };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n < 0)
        return -1;
    buf[len - 1] = '\0';
    return 0;
}

static int send_fd(int sock, int fd) {
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(int))];
    struct iovec iov;
    char dummy = 'F';

    iov.iov_base = &dummy;
    iov.iov_len  = 1;

    msg.msg_iov    = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control    = buf;
    msg.msg_controllen = sizeof(buf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

static int recv_fd(int sock) {
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(int))];
    struct iovec iov;
    char dummy;
    int fd = -1;

    iov.iov_base = &dummy;
    iov.iov_len  = 1;

    msg.msg_iov    = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control    = buf;
    msg.msg_controllen = sizeof(buf);

    if (recvmsg(sock, &msg, 0) < 0)
        return -1;

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg && cmsg->cmsg_level == SOL_SOCKET &&
        cmsg->cmsg_type == SCM_RIGHTS) {
        memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    }
    return fd;
}

static void handle_openat(struct seccomp_notif *req,
                           struct seccomp_notif_resp *resp) {
    char path_buf[PATH_BUFLEN];
    uint64_t path_ptr = req->data.args[1];

    if (read_tracee_string(req->pid, path_ptr, path_buf, sizeof(path_buf)) < 0) {
        resp->error = -EACCES;
        resp->flags = 0;
        return;
    }

    if (is_path_blocked(path_buf)) {
        fprintf(stderr, "[warden] BLOCKED openat: %s (pid %d)\n",
                path_buf, req->pid);
        resp->error = -EACCES;
        resp->flags = 0;
        return;
    }

    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    resp->error = 0;
    resp->val   = 0;
}

static void handle_mmap_or_mprotect(struct seccomp_notif *req,
                                      struct seccomp_notif_resp *resp) {
    (void)req;
    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    resp->error = 0;
}

static void supervisor_loop(int notif_fd, int initial_exec_allowed) {
    int exec_allowed = initial_exec_allowed;

    struct seccomp_notif *req = NULL;
    struct seccomp_notif_resp *resp = NULL;

    struct seccomp_notif_sizes sizes;
    memset(&sizes, 0, sizeof(sizes));
    if (syscall(__NR_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0) {
        perror("[warden] SECCOMP_GET_NOTIF_SIZES");
        return;
    }

    req  = calloc(1, sizes.seccomp_notif);
    resp = calloc(1, sizes.seccomp_notif_resp);
    if (!req || !resp) {
        perror("[warden] calloc");
        free(req);
        free(resp);
        return;
    }

    fprintf(stderr, "[warden] Supervisor active, monitoring syscalls...\n");

    while (1) {
        memset(req,  0, sizes.seccomp_notif);
        memset(resp, 0, sizes.seccomp_notif_resp);

        if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        resp->id = req->id;

        switch (req->data.nr) {
        case __NR_openat:
            handle_openat(req, resp);
            break;
        case __NR_open:
            {
                struct seccomp_notif fake = *req;
                fake.data.args[1] = req->data.args[0];
                handle_openat(&fake, resp);
            }
            break;
        case __NR_mmap:
        case __NR_mprotect:
            handle_mmap_or_mprotect(req, resp);
            break;

        case __NR_execve:
        case __NR_execveat:
            if (exec_allowed) {
                exec_allowed = 0;
                resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                resp->error = 0;
            } else {
                fprintf(stderr, "[warden] DENIED exec* (pid %d)\n", req->pid);
                resp->error = -EACCES;
                resp->flags = 0;
            }
            break;

        case __NR_socket:
        case __NR_connect:
        case __NR_bind:
        case __NR_listen:
        case __NR_accept:
        case __NR_accept4:
        case __NR_sendto:
        case __NR_recvfrom:
            fprintf(stderr, "[warden] DENIED networking (pid %d, nr %d)\n",
                    req->pid, req->data.nr);
            resp->error = -EACCES;
            resp->flags = 0;
            break;

        case __NR_ptrace:
            fprintf(stderr, "[warden] DENIED ptrace (pid %d)\n", req->pid);
            resp->error = -EACCES;
            resp->flags = 0;
            break;

        case __NR_prctl:
            fprintf(stderr, "[warden] DENIED prctl (pid %d)\n", req->pid);
            resp->error = -EACCES;
            resp->flags = 0;
            break;

        case __NR_seccomp:
            fprintf(stderr, "[warden] DENIED seccomp (pid %d)\n", req->pid);
            resp->error = -EACCES;
            resp->flags = 0;
            break;

        case __NR_process_vm_readv:
        case __NR_process_vm_writev:
            fprintf(stderr, "[warden] DENIED process_vm (pid %d)\n", req->pid);
            resp->error = -EACCES;
            resp->flags = 0;
            break;

        case __NR_memfd_create:
            fprintf(stderr, "[warden] DENIED memfd_create (pid %d)\n", req->pid);
            resp->error = -EACCES;
            resp->flags = 0;
            break;

        case __NR_userfaultfd:
            fprintf(stderr, "[warden] DENIED userfaultfd (pid %d)\n", req->pid);
            resp->error = -EACCES;
            resp->flags = 0;
            break;

        case __NR_mount:
            fprintf(stderr, "[warden] DENIED mount (pid %d)\n", req->pid);
            resp->error = -EACCES;
            resp->flags = 0;
            break;

        default:
            fprintf(stderr, "[warden] DENIED unknown syscall %d (pid %d)\n",
                    req->data.nr, req->pid);
            resp->error = -ENOSYS;
            resp->flags = 0;
            break;
        }

        if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0) {
            if (errno != ENOENT)
                perror("[warden] SECCOMP_IOCTL_NOTIF_SEND");
        }
    }

    free(req);
    free(resp);
    fprintf(stderr, "[warden] Supervisor exiting.\n");
}

static int install_notif_filter(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat,      22, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open,        21, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap,        20, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect,    19, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve,      18, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat,    17, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket,      16, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect,     15, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind,        14, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_listen,      13, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_accept,      12, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_accept4,     11, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto,      10, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvfrom,     9, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace,       8, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_prctl,        7, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_seccomp,      6, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_readv, 5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_writev, 4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_memfd_create, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_userfaultfd,  2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mount,        1, 0),

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    };
    struct sock_fprog prog = {
        .len    = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    return (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        perror("[warden] socketpair");
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("[warden] fork");
        return 1;
    }

    if (child == 0) {
        close(sv[0]);

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            perror("[warden-child] prctl NO_NEW_PRIVS");
            _exit(1);
        }

        int notif_fd = install_notif_filter();
        if (notif_fd < 0) {
            perror("[warden-child] seccomp install");
            _exit(1);
        }

        if (send_fd(sv[1], notif_fd) < 0) {
            perror("[warden-child] send_fd");
            _exit(1);
        }
        close(notif_fd);
        close(sv[1]);

        if (setgid(CHILD_GID) < 0 || setuid(CHILD_UID) < 0) {
            perror("[warden-child] drop privs");
            _exit(1);
        }

        execvp(argv[1], &argv[1]);
        perror("[warden-child] execvp");
        _exit(1);
    }

    close(sv[1]);

    int notif_fd = recv_fd(sv[0]);
    close(sv[0]);

    if (notif_fd < 0) {
        fprintf(stderr, "[warden] Failed to receive notification fd\n");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }

    fprintf(stderr, "[warden] Got notification fd %d for child %d\n",
            notif_fd, child);

    signal(SIGCHLD, SIG_IGN);

    supervisor_loop(notif_fd, 1);

    close(notif_fd);

    int status;
    waitpid(child, &status, WNOHANG);

    return 0;
}
