#include <glib.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>

#include "vhost-user.h"

typedef struct VhostMemoryRegion {
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
    uint64_t mmap_addr;
} VhostMemoryRegion;

typedef struct VhostMemory {
    uint32_t nregions;
    VhostMemoryRegion regions[VHOST_MEMORY_MAX_NREGIONS];
} VhostMemory;

struct VhostUser {
    GIOChannel *chan;
    VhostMemory memory;
    VirtIODevice *vdev;
};

static uintptr_t vhost_map_user_addr(VhostUser *vhost, uint64_t uaddr)
{
    uintptr_t result = 0;
    int i;

    for (i = 0; i < vhost->memory.nregions; i++) {
        VhostMemoryRegion *region = &vhost->memory.regions[i];

        if (region->userspace_addr <= uaddr
            && uaddr < (region->userspace_addr + region->memory_size)) {
            result = region->mmap_addr + uaddr - region->userspace_addr;
            break;
        }
    }

    return result;
}

void* vhost_map_guest_addr(VhostUser *vhost, uint64_t addr)
{
    uintptr_t result = 0;
    int idx;

    for (idx = 0; idx < vhost->memory.nregions; idx++) {
        VhostMemoryRegion *region = &vhost->memory.regions[idx];

        if (region->guest_phys_addr <= addr
                && addr < (region->guest_phys_addr + region->memory_size)) {
            result = region->mmap_addr + addr - region->guest_phys_addr;
            break;
        }
    }

    return (void*)result;
}

const char* vhostmsg_to_string(const VhostUserMsg* msg)
{
    switch (msg->request) {
#define CASE(REQ) case REQ: return G_STRINGIFY(REQ)
        CASE(VHOST_USER_NONE);
        CASE(VHOST_USER_GET_FEATURES);
        CASE(VHOST_USER_SET_FEATURES);
        CASE(VHOST_USER_SET_OWNER);
        CASE(VHOST_USER_RESET_OWNER);
        CASE(VHOST_USER_SET_MEM_TABLE);
        CASE(VHOST_USER_SET_LOG_BASE);
        CASE(VHOST_USER_SET_LOG_FD);
        CASE(VHOST_USER_SET_VRING_NUM);
        CASE(VHOST_USER_SET_VRING_ADDR);
        CASE(VHOST_USER_SET_VRING_BASE);
        CASE(VHOST_USER_GET_VRING_BASE);
        CASE(VHOST_USER_SET_VRING_KICK);
        CASE(VHOST_USER_SET_VRING_CALL);
        CASE(VHOST_USER_SET_VRING_ERR);
        CASE(VHOST_USER_GET_PROTOCOL_FEATURES);
        CASE(VHOST_USER_SET_PROTOCOL_FEATURES);
        CASE(VHOST_USER_GET_QUEUE_NUM);
        CASE(VHOST_USER_SET_VRING_ENABLE);
        CASE(VHOST_USER_SEND_RARP);
        CASE(VHOST_USER_MAX);
    }

    return "UNDEFINED";
}

void dump_vhostmsg(const VhostUserMsg* msg)
{
    int i = 0;

    g_debug("Cmd: %s (0x%x)", vhostmsg_to_string(msg), msg->request);
    g_debug("Flags: 0x%x", msg->flags);

    switch (msg->request) {
    case VHOST_USER_GET_FEATURES:
        break;
    case VHOST_USER_SET_FEATURES:
        g_debug("u64: 0x%"PRIx64, msg->u64);
        break;
    case VHOST_USER_SET_OWNER:
        break;
    case VHOST_USER_RESET_OWNER:
        break;
    case VHOST_USER_SET_MEM_TABLE:
        g_debug("nregions: %d", msg->memory.nregions);
        for (i = 0; i < msg->memory.nregions; i++) {
            g_debug("region: \n\tgpa = 0x%"PRIX64"\n\tsize = %"PRId64"\n\tua = 0x%"PRIx64"",
                    msg->memory.regions[i].guest_phys_addr,
                    msg->memory.regions[i].memory_size,
                    msg->memory.regions[i].userspace_addr);
        }
        break;
    case VHOST_USER_SET_LOG_BASE:
        g_debug("u64: 0x%"PRIx64"", msg->u64);
        break;
    case VHOST_USER_SET_LOG_FD:
        break;
    case VHOST_USER_SET_VRING_NUM:
        g_debug("state: %d %d", msg->state.index, msg->state.num);
        break;
    case VHOST_USER_SET_VRING_ADDR:
        g_debug("addr:\n\tidx = %d\n\tflags = 0x%x\n"
                "\tdua = 0x%"PRIx64"\n"
                "\tuua = 0x%"PRIx64"\n"
                "\taua = 0x%"PRIx64"\n"
                "\tlga = 0x%"PRIx64"\n", msg->addr.index, msg->addr.flags,
                msg->addr.desc_user_addr, msg->addr.used_user_addr,
                msg->addr.avail_user_addr, msg->addr.log_guest_addr);
        break;
    case VHOST_USER_SET_VRING_BASE:
        g_debug("state: %d %d", msg->state.index, msg->state.num);
        break;
    case VHOST_USER_GET_VRING_BASE:
        g_debug("state: %d %d", msg->state.index, msg->state.num);
        break;
    case VHOST_USER_SET_VRING_KICK:
    case VHOST_USER_SET_VRING_CALL:
    case VHOST_USER_SET_VRING_ERR:
        g_debug("u64: 0x%"PRIx64"", msg->u64);
        break;
    case VHOST_USER_GET_PROTOCOL_FEATURES:
        g_debug("u64: 0x%"PRIx64"", msg->u64);
        break;
    case VHOST_USER_SET_PROTOCOL_FEATURES:
        g_debug("u64: 0x%"PRIx64"", msg->u64);
        break;
    case VHOST_USER_GET_QUEUE_NUM:
    case VHOST_USER_SET_VRING_ENABLE:
    case VHOST_USER_SEND_RARP:
        break;
    case VHOST_USER_NONE:
    case VHOST_USER_MAX:
        break;
    }

    g_debug("................................................................................");
}

static int vhost_user_send_msg(int fd, const VhostUserMsg *msg, int *fds,
        size_t fd_num)
{
    int ret;

    struct msghdr msgh;
    struct iovec iov[1];

    size_t fd_size = fd_num * sizeof(int);
    char control[CMSG_SPACE(fd_size)];
    struct cmsghdr *cmsg;

    memset(&msgh, 0, sizeof(msgh));
    memset(control, 0, sizeof(control));

    /* set the payload */
    iov[0].iov_base = (void *) msg;
    iov[0].iov_len = VHOST_USER_HDR_SIZE + msg->size;

    msgh.msg_iov = iov;
    msgh.msg_iovlen = 1;

    if (fd_num) {
        msgh.msg_control = control;
        msgh.msg_controllen = sizeof(control);

        cmsg = CMSG_FIRSTHDR(&msgh);

        cmsg->cmsg_len = CMSG_LEN(fd_size);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        memcpy(CMSG_DATA(cmsg), fds, fd_size);
    } else {
        msgh.msg_control = 0;
        msgh.msg_controllen = 0;
    }

    do {
        ret = sendmsg(fd, &msgh, 0);
    } while (ret < 0 && errno == EINTR);

    if (ret < 0) {
        g_warning("Failed to send msg, reason: %s", strerror(errno));
    }

    return ret;
}

static int vhost_user_recv_msg(int fd, VhostUserMsg *msg, int *fds,
        size_t *fd_num)
{
    int ret;

    struct msghdr msgh;
    struct iovec iov[1];

    size_t fd_size = (*fd_num) * sizeof(int);
    char control[CMSG_SPACE(fd_size)];
    struct cmsghdr *cmsg;

    memset(&msgh, 0, sizeof(msgh));
    memset(control, 0, sizeof(control));
    *fd_num = 0;

    /* set the payload */
    iov[0].iov_base = (void *) msg;
    iov[0].iov_len = VHOST_USER_HDR_SIZE;

    msgh.msg_iov = iov;
    msgh.msg_iovlen = 1;
    msgh.msg_control = control;
    msgh.msg_controllen = sizeof(control);

    ret = recvmsg(fd, &msgh, 0);
    if (ret > 0) {
        if (msgh.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
            ret = -1;
        } else {
            cmsg = CMSG_FIRSTHDR(&msgh);
            if (cmsg && cmsg->cmsg_len > 0&&
                cmsg->cmsg_level == SOL_SOCKET &&
                cmsg->cmsg_type == SCM_RIGHTS) {
                if (fd_size >= cmsg->cmsg_len - CMSG_LEN(0)) {
                    fd_size = cmsg->cmsg_len - CMSG_LEN(0);
                    memcpy(fds, CMSG_DATA(cmsg), fd_size);
                    *fd_num = fd_size / sizeof(int);
                }
            }
        }
    }

    if (ret < 0) {
        g_warning("Failed recvmsg, reason: %s", strerror(errno));
    } else {
        read(fd, ((char*)msg) + ret, msg->size);
    }

    return ret;
}

static int handle_get_features(VhostUser *vhost, VhostUserMsg *msg)
{
    VirtIODevice *vdev = vhost->vdev;

    msg->u64 = vdev->features;
    msg->size = sizeof(msg->u64);

    return 1;
}

static int handle_set_features(VhostUser *vhost, VhostUserMsg *msg)
{
    VirtIODevice *vdev = vhost->vdev;

    g_debug("got features %" PRIx64, msg->u64);

    vdev->features = msg->u64;

    return 0;
}

static int handle_set_mem_table(VhostUser *vhost, VhostUserMsg *msg,
                                int *fds, size_t nfds)
{
    int i;

    g_debug("set mem-table %zu", nfds);

    vhost->memory.nregions = 0;
    for (i = 0; i < msg->memory.nregions; ++i) {
        g_return_val_if_fail(i < nfds, -1);
        g_return_val_if_fail(fds[i] >= 0, -1);

        VhostMemoryRegion *region = &vhost->memory.regions[i];

        region->guest_phys_addr = msg->memory.regions[i].guest_phys_addr;
        region->memory_size = msg->memory.regions[i].memory_size;
        region->userspace_addr = msg->memory.regions[i].userspace_addr;

        region->mmap_addr =
            (uintptr_t) mmap(0, region->memory_size, PROT_READ|PROT_WRITE,
                             MAP_SHARED, fds[i], 0);
        g_return_val_if_fail(region->mmap_addr != (uintptr_t) MAP_FAILED, -1);

        region->mmap_addr += msg->memory.regions[i].mmap_offset;
    }

    vhost->memory.nregions = i;

    return 0;
}

static int handle_set_vring_num(VhostUser *vhost, VhostUserMsg *msg)
{
    VirtIODevice *vdev = vhost->vdev;
    g_debug("vring num %x:%x", msg->state.index, msg->state.num);

    int i = msg->state.index;

    g_return_val_if_fail(i < VIRTIO_QUEUE_MAX, -1);

    vdev->vq[i].vring.num = msg->state.num;

    return 0;
}

static int handle_set_vring_addr(VhostUser *vhost, VhostUserMsg *msg)
{
    VirtIODevice *vdev = vhost->vdev;
    int i = msg->addr.index;

    g_debug("vring addr %x", i);

    g_return_val_if_fail(i < VIRTIO_QUEUE_MAX, -1);

    vdev->vq[i].vring.desc =
        (struct vring_desc*) vhost_map_user_addr(vhost, msg->addr.desc_user_addr);
    g_return_val_if_fail(vdev->vq[i].vring.desc != NULL, -1);

    vdev->vq[i].vring.avail =
        (struct vring_avail*) vhost_map_user_addr(vhost, msg->addr.avail_user_addr);
    g_return_val_if_fail(vdev->vq[i].vring.avail != NULL, -1);

    vdev->vq[i].vring.used =
        (struct vring_used*) vhost_map_user_addr(vhost, msg->addr.used_user_addr);
    g_return_val_if_fail(vdev->vq[i].vring.used != NULL, -1);

    /* vring_table.vring[i].flags = msg->addr.flags; */
    /* vring_table.vring[i].last_used_idx = vring_table.vring[i].used->idx; */
    /* vring_table.vring[i].log_guest_addr = msg->addr.log_guest_addr; */

    return 0;
}

static int handle_set_vring_base(VhostUser *vhost, VhostUserMsg *msg)
{
    VirtIODevice *vdev = vhost->vdev;
    int i = msg->addr.index;

    g_debug("vring base %x", i);

    g_return_val_if_fail(i < VIRTIO_QUEUE_MAX, -1);

    vdev->vq[i].last_avail_idx = msg->state.num;

    return 0;
}

static int handle_get_vring_base(VhostUser *vhost, VhostUserMsg *msg)
{
    VirtIODevice *vdev = vhost->vdev;
    int i = msg->state.index;

    g_debug("get vring base %x", i);

    g_return_val_if_fail(i < VIRTIO_QUEUE_MAX, -1);

    msg->state.num = vdev->vq[i].last_avail_idx;
    msg->size = sizeof(msg->state);

    return 1;
}

static int handle_set_vring_call(VhostUser *vhost, VhostUserMsg *msg,
                                 int *fds, size_t nfds)
{
    VirtIODevice *vdev = vhost->vdev;

    g_debug("set vring call %zu", nfds);

    int i = msg->u64 & VHOST_USER_VRING_IDX_MASK;
    int validfd = (msg->u64 & VHOST_USER_VRING_NOFD_MASK) == 0;

    g_return_val_if_fail(i < VIRTIO_QUEUE_MAX, -1);

    if (validfd) {
        g_return_val_if_fail(nfds == 1, -1);

        close(vdev->vq[i].callfd);
        vdev->vq[i].callfd = fds[0];
    }

    return 0;
}

static gboolean
kick_watch(GIOChannel *source, GIOCondition condition,
           gpointer data)
{
    VirtQueue *vq = data;
    int kickfd = g_io_channel_unix_get_fd(source);
    uint64_t kick_it = 0;
    int r;

    r = read(kickfd, &kick_it, sizeof(kick_it));

    if (r < 0) {
        g_error("recv kick");
    } else if (r == 0) {
        g_warning("Kick fd closed");
        return FALSE;
    } else {
        virtio_queue_notify_vq(vq);
    }

    return TRUE;
}

static int handle_set_vring_kick(VhostUser *vhost, VhostUserMsg *msg,
                                 int *fds, size_t nfds)
{
    VirtIODevice *vdev = vhost->vdev;

    g_debug("set vring kick %zu", nfds);

    int i = msg->u64 & VHOST_USER_VRING_IDX_MASK;
    int validfd = (msg->u64 & VHOST_USER_VRING_NOFD_MASK) == 0;

    g_return_val_if_fail(i < VIRTIO_QUEUE_MAX, -1);

    if (validfd) {
        g_return_val_if_fail(nfds == 1, -1);

        if (vdev->vq[i].kickchan) {
            g_source_remove(vdev->vq[i].kicksource);
            g_io_channel_unref(vdev->vq[i].kickchan);
        }
        close(vdev->vq[i].kickfd);

        vdev->vq[i].kickfd = fds[0];
        vdev->vq[i].kickchan = g_io_channel_unix_new(fds[0]);
        vdev->vq[i].kicksource = g_io_add_watch(vdev->vq[i].kickchan,
                                                G_IO_IN|G_IO_HUP, kick_watch,
                                                vdev->vq + i);
    }

    return 0;
}

static int handle_message(VhostUser *vhost, VhostUserMsg *msg,
                          int *fds, size_t nfds)
{
    int ret = 0;

    dump_vhostmsg(msg);

    switch (msg->request) {
    case VHOST_USER_GET_FEATURES:
        ret = handle_get_features(vhost, msg);
        break;
    case VHOST_USER_SET_FEATURES:
        ret = handle_set_features(vhost, msg);
        break;
    case VHOST_USER_SET_MEM_TABLE:
        ret = handle_set_mem_table(vhost, msg, fds, nfds);
        break;
    case VHOST_USER_SET_VRING_CALL:
        ret = handle_set_vring_call(vhost, msg, fds, nfds);
        break;
    case VHOST_USER_SET_VRING_KICK:
        ret = handle_set_vring_kick(vhost, msg, fds, nfds);
        break;
    case VHOST_USER_SET_VRING_NUM:
        ret = handle_set_vring_num(vhost, msg);
        break;
    case VHOST_USER_SET_VRING_BASE:
        ret = handle_set_vring_base(vhost, msg);
        break;
    case VHOST_USER_SET_VRING_ADDR:
        ret = handle_set_vring_addr(vhost, msg);
        break;
    case VHOST_USER_GET_VRING_BASE:
        ret = handle_get_vring_base(vhost, msg);
        break;
    default:
        g_debug("unhandled message %x", msg->request);
    }

    return ret;
}

static gboolean
vhost_watch(GIOChannel *source, GIOCondition condition,
            gpointer data)
{
    VhostUser *vhost = data;
    VhostUserMsg msg;
    int r, fds[10];
    size_t nfds = 10;
    int sock = g_io_channel_unix_get_fd(source);

    g_debug("Got vhost condition %x", condition);

    r = vhost_user_recv_msg(sock, &msg, fds, &nfds);
    if (r < 0) {
        perror("recv");
    } else if (r == 0) {
        close(sock);
    } else {
        r = handle_message(vhost, &msg, fds, nfds);

        if (r > 0) {
            /* Set the version in the flags when sending the reply */
            msg.flags &= ~VHOST_USER_VERSION_MASK;
            msg.flags |= VHOST_USER_VERSION;
            msg.flags |= VHOST_USER_REPLY_MASK;
            if (vhost_user_send_msg(sock, &msg, 0, 0) < 0) {
                perror("send");
            }
        }
    }

    return TRUE;
}

VhostUser *vhost_user_new(int vhostfd, VirtIODevice *vdev)
{
    VhostUser *vhost = g_new0(VhostUser, 1);

    vhost->chan = g_io_channel_unix_new(vhostfd);
    vhost->vdev = vdev;
    g_io_add_watch(vhost->chan, G_IO_IN|G_IO_HUP, vhost_watch, vhost);

    return vhost;
}
