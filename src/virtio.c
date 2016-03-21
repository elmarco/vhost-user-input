/*
 * Virtio Support
 *
 * Copyright IBM, Corp. 2007
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include <glib.h>
#include <unistd.h>
#include "virtio-ring.h"
#include "virtio.h"

#define barrier()   ({ asm volatile("" ::: "memory"); (void)0; })
#define smp_mb()    ({ barrier(); __atomic_thread_fence(__ATOMIC_SEQ_CST); barrier(); })
#define smp_wmb()   ({ barrier(); __atomic_thread_fence(__ATOMIC_RELEASE); barrier(); })
#define smp_rmb()   ({ barrier(); __atomic_thread_fence(__ATOMIC_ACQUIRE); barrier(); })

static inline uint16_t vring_avail_flags(VirtQueue *vq)
{
    return vq->vring.avail->flags;
}

static inline uint16_t vring_avail_idx(VirtQueue *vq)
{
    vq->shadow_avail_idx = vq->vring.avail->idx;

    return vq->shadow_avail_idx;
}

static inline uint16_t vring_avail_ring(VirtQueue *vq, int i)
{
    return vq->vring.avail->ring[i];
}

static inline uint16_t vring_get_used_event(VirtQueue *vq)
{
    return vring_avail_ring(vq, vq->vring.num);
}

static int virtqueue_num_heads(VirtQueue *vq, unsigned int idx)
{
    uint16_t num_heads = vring_avail_idx(vq) - idx;

    /* Check it isn't doing very strange things with descriptor numbers. */
    if (num_heads > vq->vring.num) {
        g_error("Guest moved used index from %u to %u",
                idx, vq->shadow_avail_idx);
    }
    /* On success, callers read a descriptor at vq->last_avail_idx.
     * Make sure descriptor read does not bypass avail index read. */
    if (num_heads) {
        smp_rmb();
    }

    return num_heads;
}

static unsigned int virtqueue_get_head(VirtQueue *vq, unsigned int idx)
{
    unsigned int head;

    /* Grab the next descriptor number they're advertising, and increment
     * the index we've seen. */
    head = vring_avail_ring(vq, idx % vq->vring.num);

    /* If their number is silly, that's a fatal mistake. */
    if (head >= vq->vring.num) {
        g_error("Guest says index %u is available", head);
    }

    return head;
}

static unsigned virtqueue_read_next_desc(VirtIODevice *vdev, struct vring_desc *desc,
                                         int i, unsigned int max)
{
    unsigned int next;

    /* If this descriptor says it doesn't chain, we're done. */
    if (!(desc[i].flags & VRING_DESC_F_NEXT)) {
        return max;
    }

    /* Check they're not leading us off end of descriptors. */
    next = desc[i].next;
    /* Make sure compiler knows to grab that: we don't want it changing! */
    smp_wmb();

    if (next >= max) {
        g_error("Desc next is %u", next);
    }

    return next;
}

void virtqueue_get_avail_bytes(VirtQueue *vq, unsigned int *in_bytes,
                               unsigned int *out_bytes,
                               unsigned max_in_bytes, unsigned max_out_bytes)
{
    unsigned int idx;
    unsigned int total_bufs, in_total, out_total;

    idx = vq->last_avail_idx;

    total_bufs = in_total = out_total = 0;
    while (virtqueue_num_heads(vq, idx)) {
        VirtIODevice *vdev = vq->vdev;
        unsigned int max, num_bufs, indirect = 0;
        struct vring_desc *desc;
        int i;

        max = vq->vring.num;
        num_bufs = total_bufs;
        i = virtqueue_get_head(vq, idx++);
        desc = vq->vring.desc;

        if (desc[i].flags & VRING_DESC_F_INDIRECT) {
            if (desc[i].len % sizeof(struct vring_desc)) {
                g_error("Invalid size for indirect buffer table");
            }

            /* If we've got too many, that implies a descriptor loop. */
            if (num_bufs >= max) {
                g_error("Looped descriptor");
            }

            /* loop over the indirect descriptor table */
            indirect = 1;
            max = desc[i].len / sizeof(struct vring_desc);
            desc = vdev->map(vdev, desc[i].addr);
            num_bufs = i = 0;
        }

        do {
            /* If we've got too many, that implies a descriptor loop. */
            if (++num_bufs > max) {
                g_error("Looped descriptor");
            }

            if (desc[i].flags & VRING_DESC_F_WRITE) {
                in_total += desc[i].len;
            } else {
                out_total += desc[i].len;
            }
            if (in_total >= max_in_bytes && out_total >= max_out_bytes) {
                goto done;
            }
        } while ((i = virtqueue_read_next_desc(vdev, desc, i, max)) != max);

        if (!indirect)
            total_bufs = num_bufs;
        else
            total_bufs++;
    }
done:
    if (in_bytes) {
        *in_bytes = in_total;
    }
    if (out_bytes) {
        *out_bytes = out_total;
    }
}

/* Fetch avail_idx from VQ memory only when we really need to know if
 * guest has added some buffers. */
static int virtio_queue_empty(VirtQueue *vq)
{
    if (vq->shadow_avail_idx != vq->last_avail_idx) {
        return 0;
    }

    return vring_avail_idx(vq) == vq->last_avail_idx;
}

/* The following is used with USED_EVENT_IDX and AVAIL_EVENT_IDX */
/* Assuming a given event_idx value from the other side, if
 * we have just incremented index from old to new_idx,
 * should we trigger an event? */
static inline int vring_need_event(uint16_t event_idx, uint16_t new_idx, uint16_t old)
{
    /* Note: Xen has similar logic for notification hold-off
     * in include/xen/interface/io/ring.h with req_event and req_prod
     * corresponding to event_idx + 1 and new_idx respectively.
     * Note also that req_event and req_prod in Xen start at 1,
     * event indexes in virtio start at 0. */
    return (uint16_t)(new_idx - event_idx - 1) < (uint16_t)(new_idx - old);
}

static inline bool virtio_has_feature(uint64_t features, unsigned int fbit)
{
    g_assert(fbit < 64);
    return !!(features & (1ULL << fbit));
}

static inline bool virtio_vdev_has_feature(VirtIODevice *vdev,
                                           unsigned int fbit)
{
    return virtio_has_feature(vdev->features, fbit);
}

static bool vring_notify(VirtIODevice *vdev, VirtQueue *vq)
{
    uint16_t old, new;
    bool v;
    /* We need to expose used array entries before checking used event. */
    smp_mb();

#if 0
    /* Always notify when queue is empty (when feature acknowledge) */
    if (virtio_vdev_has_feature(vdev, VIRTIO_F_NOTIFY_ON_EMPTY) &&
        !vq->inuse && virtio_queue_empty(vq)) {
        return true;
    }
#endif

    if (!virtio_vdev_has_feature(vdev, VIRTIO_RING_F_EVENT_IDX)) {
        return !(vring_avail_flags(vq) & VRING_AVAIL_F_NO_INTERRUPT);
    }

    v = vq->signalled_used_valid;
    vq->signalled_used_valid = true;
    old = vq->signalled_used;
    new = vq->signalled_used = vq->used_idx;
    return !v || vring_need_event(vring_get_used_event(vq), new, old);
}

void virtio_notify(VirtIODevice *vdev, VirtQueue *vq)
{
    uint64_t call_it = 1;

    if (!vring_notify(vdev, vq)) {
        return;
    }

    write(vq->callfd, &call_it, sizeof(call_it));
    fsync(vq->callfd);
}

static inline void vring_set_avail_event(VirtQueue *vq, uint16_t val)
{
    if (!vq->notification) {
        return;
    }

    *((uint16_t *) &vq->vring.used->ring[vq->vring.num]) = val;
}

static void virtqueue_map_desc(VirtIODevice *vdev,
                               unsigned int *p_num_sg, struct iovec *iov,
                               unsigned int max_num_sg, bool is_write,
                               uint64_t pa, size_t sz)
{
    unsigned num_sg = *p_num_sg;

    g_assert(num_sg <= max_num_sg);

    while (sz) {
        uint64_t len = sz;

        if (num_sg == max_num_sg) {
            g_error("virtio: too many write descriptors in indirect table");
        }

        iov[num_sg].iov_base = vdev->map(vdev, pa);
        iov[num_sg].iov_len = len;

        sz -= len;
        pa += len;
        num_sg++;
    }
    *p_num_sg = num_sg;
}

/* Round number down to multiple */
#define ALIGN_DOWN(n, m) ((n) / (m) * (m))

/* Round number up to multiple */
#define ALIGN_UP(n, m) ALIGN_DOWN((n) + (m) - 1, (m))

static void *virtqueue_alloc_element(size_t sz, unsigned out_num, unsigned in_num)
{
    VirtQueueElement *elem;
    size_t in_sg_ofs = ALIGN_UP(sz, __alignof__(elem->in_sg[0]));
    size_t out_sg_ofs = in_sg_ofs + in_num * sizeof(elem->in_sg[0]);
    size_t out_sg_end = out_sg_ofs + out_num * sizeof(elem->out_sg[0]);

    g_assert(sz >= sizeof(VirtQueueElement));
    elem = g_malloc(out_sg_end);
    elem->out_num = out_num;
    elem->in_num = in_num;
    elem->in_sg = (void *)elem + in_sg_ofs;
    elem->out_sg = (void *)elem + out_sg_ofs;
    return elem;
}

void *virtqueue_pop(VirtQueue *vq, size_t sz)
{
    unsigned int i, head, max;
    VirtIODevice *vdev = vq->vdev;
    VirtQueueElement *elem;
    unsigned out_num, in_num;
    struct iovec iov[VIRTQUEUE_MAX_SIZE];
    struct vring_desc *desc;

    if (virtio_queue_empty(vq)) {
        return NULL;
    }
    /* Needed after virtio_queue_empty(), see comment in
     * virtqueue_num_heads(). */
    smp_rmb();

    /* When we start there are none of either input nor output. */
    out_num = in_num = 0;

    max = vq->vring.num;

    i = head = virtqueue_get_head(vq, vq->last_avail_idx++);
    if (virtio_vdev_has_feature(vdev, VIRTIO_RING_F_EVENT_IDX)) {
        vring_set_avail_event(vq, vq->last_avail_idx);
    }

    desc = vq->vring.desc;
    if (desc[i].flags & VRING_DESC_F_INDIRECT) {
        if (desc[i].len % sizeof(struct vring_desc)) {
            g_error("Invalid size for indirect buffer table");
        }

        /* loop over the indirect descriptor table */
        max = desc[i].len / sizeof(struct vring_desc);
        desc = vdev->map(vdev, desc[i].addr);
    }

    /* Collect all the descriptors */
    do {
        if (desc[i].flags & VRING_DESC_F_WRITE) {
            virtqueue_map_desc(vdev, &in_num, iov + out_num,
                               VIRTQUEUE_MAX_SIZE - out_num, true, desc[i].addr, desc[i].len);
        } else {
            if (in_num) {
                g_error("Incorrect order for descriptors");
            }
            virtqueue_map_desc(vdev, &out_num, iov,
                               VIRTQUEUE_MAX_SIZE, false, desc[i].addr, desc[i].len);
        }

        /* If we've got too many, that implies a descriptor loop. */
        if ((in_num + out_num) > max) {
            g_error("Looped descriptor");
        }
    } while ((i = virtqueue_read_next_desc(vdev, desc, i, max)) != max);

    /* Now copy what we have collected and mapped */
    elem = virtqueue_alloc_element(sz, out_num, in_num);
    elem->index = head;
    for (i = 0; i < out_num; i++) {
        elem->out_sg[i] = iov[i];
    }
    for (i = 0; i < in_num; i++) {
        elem->in_sg[i] = iov[out_num + i];
    }

    vq->inuse++;

    return elem;
}

static inline void vring_used_write(VirtQueue *vq, struct vring_used_elem *uelem,
                                    int i)
{
    vq->vring.used->ring[i] = *uelem;
}

static void virtqueue_fill(VirtQueue *vq, const VirtQueueElement *elem,
                    unsigned int len, unsigned int idx)
{
    struct vring_used_elem uelem;

    idx = (idx + vq->used_idx) % vq->vring.num;

    uelem.id = elem->index;
    uelem.len = len;
    vring_used_write(vq, &uelem, idx);
}

static inline void vring_used_idx_set(VirtQueue *vq, uint16_t val)
{
    vq->vring.used->idx = val;
    vq->used_idx = val;
}

void virtqueue_flush(VirtQueue *vq, unsigned int count)
{
    uint16_t old, new;
    /* Make sure buffer is written before we update index. */
    smp_wmb();

    old = vq->used_idx;
    new = old + count;
    vring_used_idx_set(vq, new);
    vq->inuse -= count;
    if (G_UNLIKELY((int16_t)(new - vq->signalled_used) < (uint16_t)(new - old)))
        vq->signalled_used_valid = false;
}

void virtqueue_push(VirtQueue *vq, const VirtQueueElement *elem,
                    unsigned int len)
{
    virtqueue_fill(vq, elem, len, 0);
    virtqueue_flush(vq, 1);
}

void virtio_device_init(VirtIODevice *vdev,
                        void* (*map)(VirtIODevice *vdev, uint64_t addr))
{
    int i;

    vdev->map = map;
    for (i = 0; i < VIRTIO_QUEUE_MAX; i++) {
        vdev->vq[i].vector = VIRTIO_NO_VECTOR;
        vdev->vq[i].vdev = vdev;
        vdev->vq[i].queue_index = i;
        vdev->vq[i].callfd = -1;
        vdev->vq[i].kickfd = -1;
    }
}

VirtQueue *virtio_add_queue(VirtIODevice *vdev, int queue_size,
                            void (*handle_output)(VirtIODevice *, VirtQueue *))
{
    int i;

    for (i = 0; i < VIRTIO_QUEUE_MAX; i++) {
        if (vdev->vq[i].vring.num == 0)
            break;
    }

    if (i == VIRTIO_QUEUE_MAX || queue_size > VIRTQUEUE_MAX_SIZE)
        g_error("Too many queues");

    vdev->vq[i].vring.num = queue_size;
    vdev->vq[i].vring.num_default = queue_size;
    vdev->vq[i].vring.align = VIRTIO_PCI_VRING_ALIGN;
    vdev->vq[i].handle_output = handle_output;

    return &vdev->vq[i];
}

void virtio_queue_notify_vq(VirtQueue *vq)
{
    if (vq->vring.desc && vq->handle_output) {
        VirtIODevice *vdev = vq->vdev;

        vq->handle_output(vdev, vq);
    }
}

void virtio_queue_notify(VirtIODevice *vdev, int n)
{
    virtio_queue_notify_vq(&vdev->vq[n]);
}
