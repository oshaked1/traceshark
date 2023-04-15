#include "trace-cmd.h"

#ifndef __WTAP_TRACESHARK_H__
#define __WTAP_TRACESHARK_H__

#define BLOCK_TYPE_EVENT        0x80000001
#define BLOCK_TYPE_EVENT_FORMAT 0x80000002

#define EVENT_TYPE_UNKNOWN              0
#define EVENT_TYPE_LINUX_TRACE_EVENT    1

#define EVENT_FORMATS_KEY(machine_id, event_type) (((guint64)(machine_id) << 32) + (event_type))

struct event_options {
    guint32 machine_id;
    guint16 event_type;
    union {
        struct linux_trace_event_options linux_trace_event;
    } type_specific_options;
};

struct dumper_cb_data {
    wtap_dumper *wdh;
    int *err;
    gboolean success;
};

struct traceshark_wblock_event_format_data {
    guint32 machine_id;
    guint16 event_type;
    Buffer *format_data;
};

struct traceshark_wblock_custom_data {
    union {
        struct traceshark_wblock_event_format_data event_format_data;
    } data;
};

gboolean traceshark_process_event_format_data(wtap *wth, guint32 machine_id, guint16 event_type, const Buffer *format_data, gboolean byte_swapped);

void destroy_buffer_cb(gpointer pbuf);

void traceshark_write_event_format_block(gpointer key, gpointer value, gpointer user_data);

#endif /* __WTAP_TRACESHARK_H__ */