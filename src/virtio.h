#ifndef VIRTIO_H_
#define VIRTIO_H_

#include <inttypes.h>
#include <stdbool.h>
#include <glib.h>
#include "iov.h"

typedef struct VirtQueue VirtQueue;
typedef struct VirtIODevice VirtIODevice;

typedef struct VRing
{
    unsigned int num;
    unsigned int num_default;
    unsigned int align;
    struct vring_desc *desc;
    struct vring_avail *avail;
    struct vring_used *used;
} VRing;

struct VirtQueue
{
    VRing vring;

    /* Next head to pop */
    uint16_t last_avail_idx;

    /* Last avail_idx read from VQ. */
    uint16_t shadow_avail_idx;

    uint16_t used_idx;

    /* Last used index value we have signalled on */
    uint16_t signalled_used;

    /* Last used index value we have signalled on */
    bool signalled_used_valid;

    /* Notification enabled? */
    bool notification;

    uint16_t queue_index;

    int inuse;

    uint16_t vector;
    void (*handle_output)(VirtIODevice *vdev, VirtQueue *vq);

    VirtIODevice *vdev;

    int callfd;

    int kickfd;
    GIOChannel *kickchan;
    guint kicksource;
};

typedef struct VirtQueueElement
{
    unsigned int index;
    unsigned int out_num;
    unsigned int in_num;
    struct iovec *in_sg;
    struct iovec *out_sg;
} VirtQueueElement;

#define VIRTIO_QUEUE_MAX 1024
#define VIRTIO_NO_VECTOR 0xffff
#define VIRTQUEUE_MAX_SIZE 1024
#define VIRTIO_PCI_VRING_ALIGN 4096

struct VirtIODevice {
    VirtQueue vq[VIRTIO_QUEUE_MAX];

    uint64_t features;
    void* (*map)(VirtIODevice *vdev, uint64_t addr);
};

void virtio_device_init(VirtIODevice *vdev,
                        void* (*map)(VirtIODevice *vdev, uint64_t addr));
VirtQueue *virtio_add_queue(VirtIODevice *vdev, int queue_size,
                            void (*handle_output)(VirtIODevice *, VirtQueue *));

void virtqueue_get_avail_bytes(VirtQueue *vq, unsigned int *in_bytes,
                                   unsigned int *out_bytes,
                                   unsigned max_in_bytes, unsigned max_out_bytes);

void virtio_notify(VirtIODevice *vdev, VirtQueue *vq);

void *virtqueue_pop(VirtQueue *vq, size_t sz);
void virtqueue_push(VirtQueue *vq, const VirtQueueElement *elem,
                        unsigned int len);

void virtio_queue_notify_vq(VirtQueue *vq);

#endif
