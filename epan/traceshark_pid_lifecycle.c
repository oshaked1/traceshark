#include "traceshark.h"

#define PID_LIFECYCLE_KEY(machine_id, pid) (((guint64)(machine_id) << 32) + (pid.raw))

// map of machine ID and PID to PID lifecycle events
wmem_map_t *pid_lifecycles = NULL;

struct process_fork_info {
    union pid child_pid;
    const gchar *child_name;
};

struct process_start_info {
    const gchar *name;
    union pid parent_pid;
};

struct process_event {
    union pid pid;
    guint32 framenum;
    enum process_event_type event_type;
    union {
        const void *raw_ptr;
        const struct process_fork_info *fork;
        const struct process_start_info *start;
    } event_info;
    struct process_info *process; /* Process information as it was after the event occurred */
};

static struct process_info *generate_empty_process_info(union pid pid)
{
    struct process_info *process = wmem_new0(wmem_packet_scope(), struct process_info);
    process->pid = pid;
    return process;
}

static const struct process_event *get_preceding_event(GTree *lifecycle, const nstime_t *ts)
{
    GTreeNode *res;

    // lower bound returns the first entry that has an equal or larger ts,
    // and its previous entry will be the last one before our ts.
    if ((res = g_tree_lower_bound(lifecycle, ts)) != NULL) {
        if ((res = g_tree_node_previous(res)) != NULL)
            return (struct process_event *)g_tree_node_value(res);
        
        // no previous entry
        return NULL;
    }

    // no lower bound, the last entry will be before our ts
    if ((res = g_tree_node_last(lifecycle)) != NULL)
        return (struct process_event *)g_tree_node_value(res);
    
    // no last entry, which means the tree is empty (this shouldn't happen but we don't care if it does)
    return NULL;
}

const struct process_info *traceshark_get_process_info(guint32 machine_id, union pid pid, const nstime_t *ts)
{
    guint64 key;
    GTree *lifecycle;
    const struct process_event *event;

    // check if PID lifecycles map is initialized
    if (pid_lifecycles == NULL)
        return generate_empty_process_info(pid);

    // lookup the PID lifecycle tree
    key = PID_LIFECYCLE_KEY(machine_id, pid);
    if ((lifecycle = wmem_map_lookup(pid_lifecycles, &key)) == NULL)
        return generate_empty_process_info(pid);
    
    /**
     * Try finding a lifecycle event that happened at the same time as the given ts.
     * If no such event exists, get the last event that happened before it.
     * If that doesn't exist, generate an empty process struct.
     * If an appropriate lifecycle event is found, return the associated process struct.
     */
    if ((event = g_tree_lookup(lifecycle, ts)) != NULL)
        return event->process;
    
    if ((event = get_preceding_event(lifecycle, ts)) != NULL)
        return event->process;
    
    return generate_empty_process_info(pid);
}

static void destroy_lifecycle_cb(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
    g_tree_destroy((GTree *)value);
}

static gboolean pid_lifecycles_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data _U_)
{
    wmem_map_foreach(pid_lifecycles, destroy_lifecycle_cb, NULL);

    // return TRUE so this callback isn't unregistered
    return TRUE;
}

static void reset_process_info(struct process_info *process)
{
    wmem_free(wmem_file_scope(), process->name);
    memset(process, 0, sizeof(struct process_info));
}

static void copy_process_info(const struct process_info *src, struct process_info *dst)
{
    dst->pid = src->pid;

    if (src->name != NULL)
        dst->name = wmem_strdup(wmem_file_scope(), src->name);
    
    dst->start_framenum = src->start_framenum;
}

static void update_process_info(struct process_event *event)
{
    event->process->pid = event->pid;

    switch (event->event_type) {
        case PROCESS_NO_EVENT:
            break;
        
        case PROCESS_FORK:
            // assume parent's name is the same as the child's name
            if (event->event_info.fork->child_name != NULL)
                event->process->name = wmem_strdup(wmem_file_scope(), event->event_info.fork->child_name);
            
            break;
        
        case PROCESS_START:
            event->process->start_framenum = event->framenum;

            if (event->event_info.start->name != NULL)
                event->process->name = wmem_strdup(wmem_file_scope(), event->event_info.start->name);
            
            break;
        
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }
}

static void find_missing_info(GTreeNode *node)
{
    struct process_info *process;
    GTreeNode *curr_node;
    struct process_event *curr_event;
    gboolean stop = FALSE;

    process = ((struct process_event *)g_tree_node_value(node))->process;

    // represent all missing pieces of information as a bitfield
    union {
        guint32 raw;
        struct {
            guint32 name:1, unused:31;
        };
    } missing;

    missing.raw = 0;

    // find what's missing
    if (process->name == NULL)
        missing.name = 1;
    
    // walk events forwards, searching for missing info
    curr_node = g_tree_node_next(node);

    while (curr_node != NULL && missing.raw != 0) {
        curr_event = g_tree_node_value(curr_node);

        switch (curr_event->event_type) {
            case PROCESS_FORK:
                // assume parent's name is the same as the child's name
                if (missing.name) {
                    process->name = wmem_strdup(wmem_file_scope(), curr_event->event_info.fork->child_name);
                    missing.name = 0;
                }
                
                break;
            
            case PROCESS_START:
                // start of new process - all info from here is invalid
                stop = TRUE;
                break;
            
            case PROCESS_EXIT:
                // end of this process - all info from here is invalid
                stop = TRUE;
                break;
            
            default:
                DISSECTOR_ASSERT_NOT_REACHED();
        }

        if (stop)
            break;

        curr_node = g_tree_node_next(curr_node);
    }
}

static gboolean calculate_process_info(GTreeNode *node, gpointer data _U_)
{
    struct process_event *event;
    const struct process_event *prev_process_event;
    gboolean copied_prev_process_info = FALSE;

    event = g_tree_node_value(node);

    // reset current process info
    if (event->process == NULL)
        event->process = wmem_new0(wmem_file_scope(), struct process_info);
    else
        reset_process_info(event->process);

    // previous event exists
    if (g_tree_node_previous(node) != NULL) {
        prev_process_event = g_tree_node_value(g_tree_node_previous(node));

        // current event is not a process start and previous event is not a process exit - copy all info from it
        if (event->event_type != PROCESS_START && prev_process_event->event_type != PROCESS_EXIT) {
            copy_process_info(prev_process_event->process, event->process);
            copied_prev_process_info = TRUE;
        }
    }

    // apply new information from this event
    update_process_info(event);

    // no previous event or previous event was a process exit - walk future events and find missing info
    if (!copied_prev_process_info)
        find_missing_info(node);
    
    // return FALSE so the traversal isn't stopped
    return FALSE;
}

static const struct process_info *pid_lifecycle_update(guint32 machine_id, union pid pid, const nstime_t *ts, guint32 framenum, enum process_event_type event_type, const void *event_info)
{
    guint64 key;
    GTree *lifecycle;
    guint64 *pkey;
    struct process_event *event;
    nstime_t *ts_copy;
    nstime_t unset_ts = NSTIME_INIT_UNSET;

    // make sure PID lifecycles map is initialized
    if (pid_lifecycles == NULL) {
        pid_lifecycles = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_int64_hash, g_int64_equal);
        wmem_register_callback(wmem_file_scope(), pid_lifecycles_destroy_cb, NULL);
    }

    key = PID_LIFECYCLE_KEY(machine_id, pid);
    lifecycle = wmem_map_lookup(pid_lifecycles, (gpointer)&key);

    // lifecycle doesn't exist - create it
    if (lifecycle == NULL) {
        lifecycle = g_tree_new((GCompareFunc)nstime_cmp);
        pkey = wmem_new(wmem_file_scope(), guint64);
        *pkey = key;
        wmem_map_insert(pid_lifecycles, pkey, lifecycle);

        // insert an initial empty lifecycle event so that trace events before the first real lifecycle event have some process information available
        pid_lifecycle_update(machine_id, pid, &unset_ts, 0, PROCESS_NO_EVENT, NULL);
    }

    // make sure there's no event with the same ts
    DISSECTOR_ASSERT_HINT(g_tree_lookup(lifecycle, ts) == NULL, "Cannot update PID lifecycle - event already exists for this exact timestamp");

    // create event
    event = wmem_new0(wmem_file_scope(), struct process_event);
    event->pid = pid;
    event->framenum = framenum;
    event->event_type = event_type;
    event->event_info.raw_ptr = event_info;

    // insert event into the lifecycle tree
    ts_copy = wmem_new(wmem_file_scope(), nstime_t);
    nstime_copy(ts_copy, ts);
    g_tree_insert(lifecycle, ts_copy, event);

    // recalculate process info for all events in this PID's lifecycle
    g_tree_foreach_node(lifecycle, calculate_process_info, NULL);

    return event->process;
}

const struct process_info *traceshark_update_process_fork(guint32 machine_id, const nstime_t *ts, guint32 framenum, union pid pid, union pid child_pid, const gchar *child_name)
{
    const struct process_info *process_info;
    struct process_fork_info *parent_fork_info;
    struct process_start_info *child_start_info;

    // create parent fork event
    parent_fork_info = wmem_new0(wmem_file_scope(), struct process_fork_info);
    parent_fork_info->child_pid = child_pid;

    if (child_name != NULL)
        parent_fork_info->child_name = wmem_strdup(wmem_file_scope(), child_name);

    // update parent
    process_info = pid_lifecycle_update(machine_id, pid, ts, framenum, PROCESS_FORK, parent_fork_info);

    // create child start event
    child_start_info = wmem_new0(wmem_file_scope(), struct process_start_info);
    child_start_info->parent_pid = pid;

    if (child_name != NULL)
        child_start_info->name = wmem_strdup(wmem_file_scope(), child_name);

    // update child
    pid_lifecycle_update(machine_id, child_pid, ts, framenum, PROCESS_START, child_start_info);

    return process_info;
}