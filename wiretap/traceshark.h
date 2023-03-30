#include "trace-cmd.h"

#ifndef __WTAP_TRACESHARK_H__
#define __WTAP_TRACESHARK_H__

#define EVENT_TYPE_UNKNOWN              0
#define EVENT_TYPE_LINUX_TRACE_EVENT    1

struct event_options {
    guint32 machine_id;
    guint16 event_type;
    union {
        struct linux_trace_event_options linux_trace_event;
    } type_specific_options;
};

#endif /* __WTAP_TRACESHARK_H__ */