#include <wireshark.h>
#include <wiretap/traceshark.h>
#include "proto.h"

#ifndef __EPAN_TRACESHARK_H__
#define __EPAN_TRACESHARK_H__

extern const value_string traceshark_event_types[];

proto_tree *
find_subtree(proto_tree *tree, gint hf);

#endif /* __EPAN_TRACESHARK_H__ */