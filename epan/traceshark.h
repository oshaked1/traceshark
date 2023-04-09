#include <wireshark.h>
#include "proto.h"

#ifndef __EPAN_TRACESHARK_H__
#define __EPAN_TRACESHARK_H__

extern const value_string traceshark_event_types[];

proto_tree *proto_find_subtree(proto_tree *tree, gint hf);

void traceshark_register_field_subscription(gchar *filter_name);
wmem_array_t *traceshark_fetch_subscribed_field_values(gchar *filter_name);
fvalue_t *traceshark_fetch_subscribed_field_single_value(gchar *filter_name);

proto_item *traceshark_proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb, const gint start, gint length, const guint encoding);
proto_item *traceshark_proto_tree_add_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint32 value);
proto_item *traceshark_proto_tree_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, const char* value);

#endif /* __EPAN_TRACESHARK_H__ */