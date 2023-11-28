#include <wireshark.h>
#include "proto.h"

#ifndef __EPAN_TRACESHARK_H__
#define __EPAN_TRACESHARK_H__

// traceshark_utils.c
gpointer g_tree_get_preceding_node(GTree *tree, gconstpointer key);
gpointer g_tree_get_following_node(GTree *tree, gconstpointer key);

// traceshark_find_subtree.c
proto_tree *proto_find_subtree(proto_tree *tree, gint hf);

// traceshark_field_subscription.c
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
proto_item *traceshark_proto_tree_add_boolean(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint32 value);

extern gboolean capture_ordered_chronologically;

typedef gint32 pid_t;

enum linux_process_info_type {
    LINUX_PROCESS_INFO_PARENT_PIID,
    LINUX_PROCESS_INFO_NAME,
    LINUX_PROCESS_INFO_EXEC_FILE,
    LINUX_PROCESS_INFO_CHILD,
    LINUX_PROCESS_INFO_THREAD
};

struct linux_thread_info {
    pid_t tid;
    pid_t creator_tid;
    pid_t prev_tid;
    guint32 tid_change_frame;
};

/**
 * @brief Represents a piece of information about a process, to be stored in an interval tree.
 * Contains the start and end frame numbers for reference (if applicable).
 * Because Wireshark frame numbers start from 1, a value of 0 indicates no information.
 */
struct time_range_info {
    nstime_t start_ts;
    guint32 start_frame;
    nstime_t end_ts;
    guint32 end_frame;
    enum linux_process_info_type info_type;
    union {
        guint32 parent_piid;
        gchar *name;
        gchar *exec_file;
        guint32 child_piid;
        struct linux_thread_info thread_info;
    } info;
};

/**
 * @brief Represents all useful information about a process, across its entire lifespan.
 * The information is stored in a way that makes it so that given a certain point in time,
 * it is possible to know which pieces of information are relevant and which are not yet or not anymore.
 */
struct linux_process_info {
    guint32 machine_id;
    
    /*
     * Because PIDs can wrap around on a system after utilizing all available PIDs,
     * we need a way to distinguish between two different processes sharing the same PID
     * in different points in time.
     * The PIID (process instance identifier) is generated for each instance of a process,
     * and is used to identify it internally instead of using the PID.
     * The PID linked to a certain PIID can change when new information is received.
     * For example, in a scenario where a process event occurs so we know the PID of the thread but
     * we don't know that it's the thread group leader - we create a new process instance with the given PID.
     * But if at a later point we discover that this PID is a thread in a process whose leader has a different PID,
     * we change the PID of the process instance.
     * 
     * A PIID of 0 indicates this is not an actual process instance and the struct is just a placeholder.
     */
    guint32 piid;
    pid_t pid; // a.k.a TGID

    guint32 start_frame;
    guint32 exit_frame;

    gboolean has_exit_code;
    gint32 exit_code;

    /*
     * All information that can change throughout the lifetime of the process is represented in trees indexed by the start time.
     * Some pieces of information, like the name, are mutually exclusive meaning they can only have a single value at any point in time.
     * Other pieces of information, like the list of threads, can have multiple values at any given time.
     * All tree nodes are struct time_range_info
     */
    GTree *parent_piid; /* LINUX_PROCESS_INFO_PARENT_PIID */
    GTree *name;        /* LINUX_PROCESS_INFO_NAME */
    GTree *exec_file;   /* LINUX_PROCESS_INFO_EXEC_FILE */
    GTree *children;    /* LINUX_PROCESS_INFO_CHILD
                         * Contains PIIDs of all processes whose parent is this process, even if not all were created by the same thread
                         */
    GTree *threads;     /* LINUX_PROCESS_INFO_THREAD */
};

struct traceshark_dissector_data {
    guint32 machine_id;
    guint16 event_type;
    union {
        pid_t linux;
    } pid;
    union {
        const struct linux_process_info *linux;
        void *raw_ptr;
    } process_info;
};

/**
 * Processes and threads in Linux are indistinguishable in many aspects,
 * so we treat events of both as process events. 
 */
enum process_event_type {
    PROCESS_FORK,
    PROCESS_EXEC,
    PROCESS_EXIT
};

/**
 * @brief Retrieve Linux process information based on a PID at a certain point in time.
 * 
 * @param machine_id The machine ID this PID belongs to.
 * @param pid The PID (identifies a single thread on Linux).
 * @param ts The timestamp in which the retrieved info is relevant.
 * @return The process information.
 */
const struct linux_process_info *traceshark_get_linux_process_by_pid(guint32 machine_id, pid_t pid, const nstime_t *ts);
const struct linux_process_info *traceshark_get_linux_process_by_piid(guint32 machine_id, guint32 piid);

const struct linux_process_info *traceshark_linux_process_get_parent(const struct linux_process_info *process, const nstime_t *ts);
const gchar *traceshark_linux_process_get_name(const struct linux_process_info *process, const nstime_t *ts);
const gchar *traceshark_linux_process_get_exec_file(const struct linux_process_info *process, const nstime_t *ts);

const struct linux_process_info *traceshark_update_linux_process_fork(guint32 machine_id, const nstime_t *ts, guint32 framenum, pid_t parent_tid, pid_t child_tid, const gchar *child_name, gboolean is_thread);
const struct linux_process_info *traceshark_update_linux_process_exec(guint32 machine_id, const nstime_t *ts, guint32 framenum, pid_t pid, const gchar *exec_file, pid_t old_tid);
const struct linux_process_info *traceshark_update_linux_process_exit_group(guint32 machine_id, const nstime_t *ts, guint32 framenum, pid_t pid, gint32 exit_code);
const struct linux_process_info *traceshark_update_linux_process_exit(guint32 machine_id, const nstime_t *ts, guint32 framenum, pid_t pid, const gchar *name);

#endif /* __EPAN_TRACESHARK_H__ */