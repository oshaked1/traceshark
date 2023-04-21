#include <wireshark.h>
#include "proto.h"

#ifndef __EPAN_TRACESHARK_H__
#define __EPAN_TRACESHARK_H__

// differentiate between Linux PIDs which are a signed 32-bit value
// and Windows PIDs which are an unsigned 32-bit value
union pid {
    gint32 linux;
    guint32 windows;
    guint32 raw;
};

struct traceshark_process {
    union pid pid;
};

struct traceshark_dissector_data {
    guint32 machine_id;
    guint16 event_type;
    struct traceshark_process *process;
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

#endif /* __EPAN_TRACESHARK_H__ */