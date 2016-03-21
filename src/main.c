#include <glib.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/input.h>
#include <endian.h>
#include <string.h>

#include "journal.h"

#include "vhost-user.h"
#include "virtio-input.h"

typedef struct VirtIOInput {
    VirtIODevice                      device;
    VhostUser                         *vhost;
    VirtQueue                         *evt, *sts;

    virtio_input_event                *queue;
    uint32_t                          qindex, qsize;
} VirtIOInput;

void virtio_input_send(VirtIOInput *vinput, virtio_input_event *event)
{
    VirtQueueElement *elem;
    unsigned have, need;
    int i, len;

    /* queue up events ... */
    if (vinput->qindex == vinput->qsize) {
        vinput->qsize++;
        vinput->queue = realloc(vinput->queue, vinput->qsize *
                                sizeof(virtio_input_event));
    }
    vinput->queue[vinput->qindex++] = *event;

    /* ... until we see a report sync ... */
    if (event->type != htole16(EV_SYN) ||
        event->code != htole16(SYN_REPORT)) {
        return;
    }

    /* ... then check available space ... */
    need = sizeof(virtio_input_event) * vinput->qindex;
    virtqueue_get_avail_bytes(vinput->evt, &have, NULL, need, 0);
    if (have < need) {
        vinput->qindex = 0;
        g_warning("ENOSPC in vq, dropping events");
        return;
    }

    /* ... and finally pass them to the guest */
    for (i = 0; i < vinput->qindex; i++) {
        elem = virtqueue_pop(vinput->evt, sizeof(VirtQueueElement));
        if (!elem) {
            /* should not happen, we've checked for space beforehand */
            g_warning("%s: Huh?  No vq elem available ...\n", __func__);
            return;
        }
        len = iov_from_buf(elem->in_sg, elem->in_num,
                           0, vinput->queue+i, sizeof(virtio_input_event));
        virtqueue_push(vinput->evt, elem, len);
        g_free(elem);
    }
    virtio_notify(&vinput->device, vinput->evt);
    vinput->qindex = 0;
}

static gboolean
evdev_watch(GIOChannel *source, GIOCondition condition,
            gpointer data)
{
    int fd = g_io_channel_unix_get_fd(source);
    VirtIOInput *vinput = data;

    g_debug("Got evdev condition %x", condition);

    struct virtio_input_event virtio;
    struct input_event evdev;
    int rc;

    for (;;) {
        rc = read(fd, &evdev, sizeof(evdev));
        if (rc != sizeof(evdev)) {
            break;
        }

        g_debug("input %d %d %d", evdev.type, evdev.code, evdev.value);

        virtio.type  = htole16(evdev.type);
        virtio.code  = htole16(evdev.code);
        virtio.value = htole32(evdev.value);
        virtio_input_send(vinput, &virtio);
    }

    return TRUE;
}

static void virtio_input_handle_evt(VirtIODevice *vdev, VirtQueue *vq)
{
    g_debug("%s", __func__);
}

static void virtio_input_handle_sts(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOInput *vinput = (VirtIOInput *)vdev;
    virtio_input_event event;
    VirtQueueElement *elem;
    int len;

    g_debug("%s", __func__);

    for (;;) {
        elem = virtqueue_pop(vinput->sts, sizeof(VirtQueueElement));
        if (!elem) {
            break;
        }

        memset(&event, 0, sizeof(event));
        len = iov_to_buf(elem->out_sg, elem->out_num,
                         0, &event, sizeof(event));
        g_debug("TODO handle status %d %p", len, elem);
        virtqueue_push(vinput->sts, elem, len);
        g_free(elem);
    }
    virtio_notify(vdev, vinput->sts);
}

void* map_handler(VirtIODevice *vdev, uint64_t addr)
{
    VirtIOInput *vinput = (VirtIOInput *)vdev;

    return vhost_map_guest_addr(vinput->vhost, addr);
}

int main(int argc, char *argv[])
{
    GMainLoop *loop = NULL;
    GError *err = NULL;
    GOptionContext *context;
    GIOChannel *evdev;
    VirtIOInput vinput = { 0, };
    int evdevfd = -1;
    int vhostfd = -1;

    GOptionEntry entries[] = {
        { "evdevfd", 0, 0, G_OPTION_ARG_INT, &evdevfd, "The evdev fd", "FD" },
        { "vhostfd", 0, 0, G_OPTION_ARG_INT, &vhostfd, "The vhost fd", "FD" },
        { NULL }
    };

    context = g_option_context_new("- vhost-user input helper");
    g_option_context_add_main_entries(context, entries, NULL);
    if (!g_option_context_parse(context, &argc, &argv, &err)) {
        g_print("option parsing failed: %s\n", err->message);
        exit(1);
    }
    if (evdevfd == -1 || vhostfd == -1) {
        g_print("Required arguments missing\n");
        exit(1);
    }

    set_journal_log_handler();

    g_printerr("Starting vhost-user-input helper %d %d", evdevfd, vhostfd);

    vinput.vhost = vhost_user_new(vhostfd, &vinput.device);

    virtio_device_init(&vinput.device, map_handler);
    vinput.evt = virtio_add_queue(&vinput.device, 64, virtio_input_handle_evt);
    vinput.sts = virtio_add_queue(&vinput.device, 64, virtio_input_handle_sts);

    evdev = g_io_channel_unix_new(evdevfd);
    g_io_add_watch(evdev, G_IO_IN|G_IO_HUP, evdev_watch, &vinput);

    loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    return 0;
}
