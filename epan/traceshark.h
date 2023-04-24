#include <wireshark.h>
#include "proto.h"

#ifndef __EPAN_TRACESHARK_H__
#define __EPAN_TRACESHARK_H__

// differentiate between Linux PIDs which are a signed 32-bit value
// and Windows PIDs which are an unsigned 32-bit value
union pid {
    gint32 _linux; // the Linux build environment predefines "linux" so we can't use it
    guint32 windows;
    guint32 raw;
};

struct traceshark_process {
    union pid pid;
    gchar *name;
};

struct traceshark_dissector_data {
    guint32 machine_id;
    guint16 event_type;
    const struct traceshark_process *process;
};

proto_tree *proto_find_subtree(proto_tree *tree, gint hf);

void traceshark_register_field_subscription(gchar *filter_name);
wmem_array_t *traceshark_subscribed_field_get_values(gchar *filter_name);
fvalue_t *traceshark_subscribed_field_get_single_value_or_null(gchar *filter_name);
fvalue_t *traceshark_subscribed_field_get_single_value(gchar *filter_name);

proto_item *traceshark_proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb, const gint start, gint length, const guint encoding);
proto_item *traceshark_proto_tree_add_int(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, gint32 value);
proto_item *traceshark_proto_tree_add_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint32 value);
proto_item *traceshark_proto_tree_add_int64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, gint64 value);
proto_item *traceshark_proto_tree_add_uint64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint64 value);
proto_item *traceshark_proto_tree_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, const char* value);

enum process_event_type {
    PROCESS_FORK,
    PROCESS_EXEC,
    PROCESS_EXIT
};

/**
 * @brief Retrieve process information based on a PID at a certain point in time.
 * 
 * @param machine_id The machine ID this PID belongs to.
 * @param pid The PID (identifies a single thread on Linux and an entire process on Windows).
 * @param ts The timestamp in which the retrieved info is relevant.
 * @return The process information.
 */
const struct traceshark_process *traceshark_get_process_info(guint32 machine_id, union pid pid, const nstime_t *ts);

struct fork_event {
    union pid parent_pid;
    union pid child_pid;
    const gchar *child_name;
};

const struct traceshark_process *traceshark_update_process_fork(guint32 machine_id, union pid pid, const nstime_t *ts, const struct fork_event *info);

#endif /* __EPAN_TRACESHARK_H__ */