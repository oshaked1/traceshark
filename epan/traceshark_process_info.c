#include "traceshark.h"

#define TASK_COMM_LEN 16

gboolean capture_ordered_chronologically = TRUE;

#define LINUX_PROCESS_KEY(machine_id, piid) (((guint64)(machine_id) << 32) + (piid))

// map of machine ID and PIID to process info
wmem_map_t *linux_process_map = NULL;

#define TID_LIFECYCLE_KEY(machine_id, tid) (((guint64)(machine_id) << 32) + (tid))

// map of machine ID and TID to TID lifecycle events
wmem_map_t *tid_lifecycle_map = NULL;

enum tid_lifecycle_event_type {
    TID_LINK,       // a TID is linked to a PIID, but the thread has existed beforehand
    TID_START,      // a thread has started and the TID is linked to a PIID
    TID_END,        // a thread has ended and is unlinked from its PIID
    TID_ZOMBIE,     // the main thread has ended but it's still linked to the PIID as other threads are active
    TID_SOFT_END    // a thread was marked as ended by an exit_group event, but it is still seen as active for following thread exit events
};

struct tid_lifecycle_event {
    enum tid_lifecycle_event_type event_type;
    guint32 piid;
};

static struct linux_process_info *get_existing_linux_process_info(guint32 machine_id, pid_t tid, const nstime_t *ts, gboolean soft_end_ok)
{
    guint64 key;
    GTree *lifecycle;
    const struct tid_lifecycle_event *event, *preceding_event, *following_event;
    guint32 piid;
    struct linux_process_info *process;

    // make sure TID lifecycles map and Linux process map are initialized
    if (tid_lifecycle_map == NULL || linux_process_map == NULL)
        return NULL;
    
    // lookup the TID lifecycle tree
    key = TID_LIFECYCLE_KEY(machine_id, tid);
    if ((lifecycle = wmem_map_lookup(tid_lifecycle_map, &key)) == NULL)
        return NULL;
    
    /**
     * Try finding a lifecycle event that happened at the same time as the given timestamp.
     * If no such event exists, get the preceding and following events and determine what PIID is relevant.
     */

    // try finding a lifecycle event that happened at the same time as the given timestamp
    if ((event = g_tree_lookup(lifecycle, ts)) != NULL)
        piid = event->piid;
    
    // no event at this exact time - find preceding and following events to determine the PIID
    else {
        preceding_event = g_tree_get_preceding_value(lifecycle, ts);

        // preceding event is a link/start/zombie event - use the linked PIID
        if (preceding_event && (preceding_event->event_type == TID_LINK
            || preceding_event->event_type == TID_START
            || preceding_event->event_type == TID_ZOMBIE))
            piid = preceding_event->piid;
        
        // preceding event is a soft end event and we're ok with that - use linked PIID
        else if (preceding_event && preceding_event->event_type == TID_SOFT_END && soft_end_ok)
            piid = preceding_event->piid;
        
        // no preceding event or it is an end event or it is a soft end event and we're not ok with that - determine PIID based on the following event
        else {
            following_event = g_tree_get_following_value(lifecycle, ts);

            // following event is a link/end/soft_end/zombie event - use the following event's PIID
            if (following_event && (following_event->event_type == TID_LINK
                                    || following_event->event_type == TID_END
                                    || following_event->event_type == TID_ZOMBIE
                                    || following_event->event_type == TID_SOFT_END))
                piid = following_event->piid;
            
            // no following event or it is a start event - PIID can't be determined
            else
                piid = 0;
        }
    }

    // no linked PIID
    if (piid == 0)
        return NULL;
    
    key = LINUX_PROCESS_KEY(machine_id, piid);
    process = wmem_map_lookup(linux_process_map, &key);
    DISSECTOR_ASSERT(process != NULL);
    return process;
}

static const struct linux_process_info *generate_anonymous_linux_process_info(pid_t pid)
{
    struct linux_process_info *process = wmem_new0(wmem_packet_scope(), struct linux_process_info);

    process->piid = 0;
    process->pid = pid;

    return process;
}

const struct linux_process_info *traceshark_get_linux_process_by_pid(guint32 machine_id, pid_t tid, const nstime_t *ts)
{
    const struct linux_process_info *process;

    if ((process = get_existing_linux_process_info(machine_id, tid, ts, FALSE)) == NULL || !capture_ordered_chronologically)
        return generate_anonymous_linux_process_info(tid);
    
    return process;
}

const struct linux_process_info *traceshark_get_linux_process_by_piid(guint32 machine_id, guint32 piid)
{
    if (!capture_ordered_chronologically)
        return NULL;
    
    guint64 key = LINUX_PROCESS_KEY(machine_id, piid);
    return wmem_map_lookup(linux_process_map, &key);
}

const struct linux_process_info *traceshark_linux_process_get_parent(const struct linux_process_info *process, const nstime_t *ts)
{
    struct time_range_info *info;

    if (!capture_ordered_chronologically)
        return NULL;

    if (process->parent_piid == NULL)
        return NULL;

    if ((info = g_tree_lookup(process->parent_piid, ts)) != NULL || (info = g_tree_get_preceding_value(process->parent_piid, ts)) != NULL)
        return traceshark_get_linux_process_by_piid(process->machine_id, info->info.parent_piid);
    
    return NULL;
}

const gchar *traceshark_linux_process_get_name(const struct linux_process_info *process, const nstime_t *ts)
{
    struct time_range_info *info;

    if (!capture_ordered_chronologically)
        return NULL;

    if (process->name == NULL)
        return NULL;

    if ((info = g_tree_lookup(process->name, ts)) != NULL || (info = g_tree_get_preceding_value(process->name, ts)) != NULL)
        return info->info.name;
    
    return NULL;
}

const gchar *traceshark_linux_process_get_prev_name(const struct linux_process_info *process, const nstime_t *ts)
{
    GTreeNode *res;
    struct time_range_info *info;

    if (!capture_ordered_chronologically)
        return NULL;

    if (process->name == NULL)
        return NULL;

    if ((res = g_tree_lookup_node(process->name, ts)) != NULL || (res = g_tree_get_preceding_node(process->name, ts)) != NULL) {
        if ((res = g_tree_node_previous(res)) != NULL) {
            if ((info = g_tree_node_value(res)) != NULL)
                return info->info.name;
        }

    }
    
    return NULL;
}

const gchar *traceshark_linux_process_get_exec_file(const struct linux_process_info *process, const nstime_t *ts)
{
    struct time_range_info *info;

    if (!capture_ordered_chronologically)
        return NULL;

    if (process->exec_file == NULL)
        return NULL;

    if ((info = g_tree_lookup(process->exec_file, ts)) != NULL || (info = g_tree_get_preceding_value(process->exec_file, ts)) != NULL)
        return info->info.exec_file;
    
    return NULL;
}

static guint32 next_piid = 1; // next PIID to allocate

static void linux_process_info_destroy_cb(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
    struct linux_process_info *process = value;

    g_tree_destroy(process->parent_piid);
    g_tree_destroy(process->name);
    g_tree_destroy(process->exec_file);
    g_tree_destroy(process->children);
    g_tree_destroy(process->threads);
}

static gboolean linux_process_map_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data _U_)
{
    // reset PIID allocator
    next_piid = 1;

    // destroy processes
    wmem_map_foreach(linux_process_map, linux_process_info_destroy_cb, NULL);

    // return TRUE so this callback isn't unregistered
    return TRUE;
}

static struct linux_process_info *create_linux_process_info(guint32 machine_id)
{
    guint32 piid;
    struct linux_process_info *process;
    guint64 *key;

    // make sure Linux process map is initialized
    if (linux_process_map == NULL) {
        linux_process_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_int64_hash, g_int64_equal);
        wmem_register_callback(wmem_file_scope(), linux_process_map_destroy_cb, NULL);
    }

    // allocate PIID and check for overflow
    piid = next_piid++;
    DISSECTOR_ASSERT_HINT(piid != 0, "Cannot allocate anymore PIIDs");

    process = wmem_new0(wmem_file_scope(), struct linux_process_info);

    process->machine_id = machine_id;
    process->piid = piid;

    // initialize time range trees
    process->name = g_tree_new((GCompareFunc)nstime_cmp);
    process->parent_piid = g_tree_new((GCompareFunc)nstime_cmp);
    process->exec_file = g_tree_new((GCompareFunc)nstime_cmp);
    process->children = g_tree_new((GCompareFunc)nstime_cmp);
    process->threads = g_tree_new((GCompareFunc)nstime_cmp);

    // insert the process into the process map
    key = wmem_new(wmem_file_scope(), guint64);
    *key = LINUX_PROCESS_KEY(machine_id, piid);
    wmem_map_insert(linux_process_map, key, process);

    return process;
}

static struct time_range_info *time_range_add(GTree *tree, const nstime_t *start_ts, guint32 start_frame)
{
    struct time_range_info *info;
    nstime_t *ts_copy = wmem_new(wmem_file_scope(), nstime_t);

    // NULL start_ts means the start time is unknown
    if (start_ts == NULL)
        nstime_set_zero(ts_copy);
    else
        nstime_copy(ts_copy, start_ts);

    // create new time range info
    info = wmem_new0(wmem_file_scope(), struct time_range_info);
    nstime_copy(&info->start_ts, ts_copy);
    info->start_frame = start_frame;
    nstime_set_unset(&info->end_ts);

    // insert new info into the tree
    g_tree_insert(tree, ts_copy, info);

    return info;
}

#define NSECS_IN_SEC 1000000000

typedef gboolean (*time_range_info_eq_func)(const struct time_range_info *prev_info, const void *arg);

static gboolean time_range_add_mutually_exclusive(struct time_range_info **info, GTree *tree, const nstime_t *start_ts, guint32 start_frame, time_range_info_eq_func time_range_info_eq, const void *time_range_info_eq_arg)
{
    struct time_range_info *prev_info;

    // unknown start time and there is already existing information
    if (start_ts == NULL && g_tree_nnodes(tree) > 0)
        return FALSE;

    // start time is known and there is an overlapping time range - mark its end
    else if (start_ts != NULL && (prev_info = g_tree_get_preceding_value(tree, start_ts)) != NULL && nstime_is_unset(&prev_info->end_ts)) {
        // same info - do nothing
        if (time_range_info_eq != NULL && time_range_info_eq(prev_info, time_range_info_eq_arg)) {
            *info = NULL;
            return TRUE;
        }
        
        prev_info->end_frame = start_frame;

        nstime_copy(&prev_info->end_ts, start_ts);

        // subtract 1 nanosecond so it doesn't appear to be valid at the start of the new time range
        if (prev_info->end_ts.nsecs > 0)
            prev_info->end_ts.nsecs--;
        else {
            prev_info->end_ts.nsecs = NSECS_IN_SEC - 1;
            prev_info->end_ts.secs--;
        }
    }

    *info = time_range_add(tree, start_ts, start_frame);
    return TRUE;
}

static gboolean parent_eq(const struct time_range_info *prev_info, const void *piid)
{
    return prev_info->info.parent_piid == *(const guint32 *)piid;
}

static gboolean linux_process_set_parent(struct linux_process_info *process, guint32 parent_piid, const nstime_t *start_ts, guint32 start_frame)
{
    struct time_range_info *info;
    gboolean success;
    
    success = time_range_add_mutually_exclusive(&info, process->parent_piid, start_ts, start_frame, parent_eq, &parent_piid);

    if (success && info != NULL) {
        info->info_type = LINUX_PROCESS_INFO_PARENT_PIID;
        info->info.parent_piid = parent_piid;
    }
    
    return success;
}

static gboolean name_eq(const struct time_range_info *prev_info, const void *name)
{
    return strcmp(prev_info->info.name, (const gchar *)name) == 0;
}

static gboolean linux_process_set_name(struct linux_process_info *process, const gchar *name, const nstime_t *start_ts, guint32 start_frame)
{
    struct time_range_info *info;
    gboolean success;
    
    success = time_range_add_mutually_exclusive(&info, process->name, start_ts, start_frame, name_eq, name);

    if (success && info != NULL) {
        info->info_type = LINUX_PROCESS_INFO_NAME;
        info->info.name = wmem_strdup(wmem_file_scope(), name);
    }

    return success;
}

static gboolean exec_file_eq(const struct time_range_info *prev_info, const void *exec_file)
{
    return strcmp(prev_info->info.exec_file, (const gchar *)exec_file) == 0;
}

static gboolean linux_process_set_exec_file(struct linux_process_info *process, const gchar *exec_file, const nstime_t *start_ts, guint32 start_frame)
{
    struct time_range_info *info;
    gboolean success;
    
    success = time_range_add_mutually_exclusive(&info, process->exec_file, start_ts, start_frame, exec_file_eq, exec_file);

    if (success && info != NULL) {
        info->info_type = LINUX_PROCESS_INFO_EXEC_FILE;
        info->info.exec_file = wmem_strdup(wmem_file_scope(), exec_file);
    }

    return success;
}

static void linux_process_add_child(struct linux_process_info *process, guint32 child_piid, const nstime_t *start_ts, guint32 start_frame)
{
    struct time_range_info *info;

    info = time_range_add(process->children, start_ts, start_frame);
    info->info_type = LINUX_PROCESS_INFO_CHILD;
    info->info.child_piid = child_piid;
}

static void linux_process_add_thread(struct linux_process_info *process, pid_t tid, pid_t creator_tid, const nstime_t *start_ts, guint32 start_frame)
{
    struct time_range_info *info;

    info = time_range_add(process->threads, start_ts, start_frame);
    info->info_type = LINUX_PROCESS_INFO_THREAD;
    info->info.thread_info.tid = tid;
    info->info.thread_info.prev_tid = tid;
    info->info.thread_info.tid_change_frame = 0;
    info->info.thread_info.creator_tid = creator_tid;
    info->info.thread_info.soft_ended = FALSE;
}

static void destroy_lifecycle_cb(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
    g_tree_destroy((GTree *)value);
}

static gboolean tid_lifecycle_map_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data _U_)
{
    wmem_map_foreach(tid_lifecycle_map, destroy_lifecycle_cb, NULL);

    // return TRUE so this callback isn't unregistered
    return TRUE;
}

static void tid_lifecycle_update(guint32 machine_id, pid_t tid, const nstime_t *ts, guint32 piid, enum tid_lifecycle_event_type event_type)
{
    guint64 key;
    GTree *lifecycle;
    guint64 *pkey;
    struct tid_lifecycle_event *event;
    nstime_t *ts_copy;

    // make sure TID lifecycles map is initialized
    if (tid_lifecycle_map == NULL) {
        tid_lifecycle_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_int64_hash, g_int64_equal);
        wmem_register_callback(wmem_file_scope(), tid_lifecycle_map_destroy_cb, NULL);
    }

    key = TID_LIFECYCLE_KEY(machine_id, tid);
    lifecycle = wmem_map_lookup(tid_lifecycle_map, (gpointer)&key);

    // lifecycle doesn't exist - create it
    if (lifecycle == NULL) {
        lifecycle = g_tree_new((GCompareFunc)nstime_cmp);
        pkey = wmem_new(wmem_file_scope(), guint64);
        *pkey = key;
        wmem_map_insert(tid_lifecycle_map, pkey, lifecycle);
    }

    // make sure there is no event at this exact time
    DISSECTOR_ASSERT_HINT(g_tree_lookup(lifecycle, ts) == NULL, "Cannot update TID lifecycle - event already exists for this exact timestamp");

    // create event
    event = wmem_new(wmem_file_scope(), struct tid_lifecycle_event);
    event->event_type = event_type;
    event->piid = piid;

    // insert event into the lifecycle tree
    ts_copy = wmem_new(wmem_file_scope(), nstime_t);
    nstime_copy(ts_copy, ts);
    g_tree_insert(lifecycle, ts_copy, event);
}

struct count_active_threads_args {
    guint32 count;
    guint32 frame;
};

static gboolean count_active_threads(gpointer key _U_, gpointer value, gpointer data)
{
    struct time_range_info *info = value;
    struct count_active_threads_args *args = data;

    if (info->end_frame == 0 || info->end_frame > args->frame)
        args->count++;
    
    // return FALSE so traversal isn't stopped
    return FALSE;
}

static guint32 num_active_threads(GTree *threads, guint32 frame)
{
    struct count_active_threads_args args = {
        .count = 0,
        .frame = frame
    };

    g_tree_foreach(threads, count_active_threads, &args);

    return args.count;
}

enum stop_thread_mode {
    STOP_MATCHING_THREAD,
    STOP_ALL_THREADS,
    STOP_ALL_SECONDARY_THREADS
};

struct stop_thread_args {
    enum stop_thread_mode mode;
    pid_t tid;
    const nstime_t *ts;
    guint32 exit_frame;
    struct linux_process_info *process;
    gboolean soft_end;
};

static gboolean stop_thread(gpointer key _U_, gpointer value, gpointer data)
{
    struct time_range_info *info = value;
    struct stop_thread_args *args = data;

    if (args->mode == STOP_ALL_THREADS ||
       (args->mode == STOP_MATCHING_THREAD && info->info.thread_info.tid == args->tid) ||
       (args->mode == STOP_ALL_SECONDARY_THREADS && info->info.thread_info.tid != args->process->pid)) {
        // thread is active or soft ended - stop it
        if (nstime_is_unset(&info->end_ts) || info->info.thread_info.soft_ended) {
            // if the main thread is being stopped while there are other running threads, only mark it as a zombie
            if (args->mode == STOP_MATCHING_THREAD
                && info->info.thread_info.tid == args->process->pid
                && num_active_threads(args->process->threads, args->exit_frame) > 1)
                tid_lifecycle_update(args->process->machine_id, info->info.thread_info.tid, args->ts, args->process->piid, TID_ZOMBIE);
            // mark as soft ended
            else if (args->soft_end) {
                info->info.thread_info.soft_ended = TRUE;
                tid_lifecycle_update(args->process->machine_id, info->info.thread_info.tid, args->ts, args->process->piid, TID_SOFT_END);
            }
            else
                tid_lifecycle_update(args->process->machine_id, info->info.thread_info.tid, args->ts, args->process->piid, TID_END);
            
            // mark the thread end time
            nstime_copy(&info->end_ts, args->ts);
            info->end_frame = args->exit_frame;

            // this was the last thread - mark the process as ended if it isn't already
            if (num_active_threads(args->process->threads, args->exit_frame) == 0 && args->process->exit_frame == 0)
                args->process->exit_frame = args->exit_frame;
        }
    }

    // return FALSE so traversal isn't stopped
    return FALSE;
}

static void linux_process_stop_thread(struct linux_process_info *process, pid_t tid, const nstime_t *ts, guint32 exit_frame)
{
    struct stop_thread_args args = {
        .mode = STOP_MATCHING_THREAD,
        .tid = tid,
        .ts = ts,
        .exit_frame = exit_frame,
        .process = process,
        .soft_end = FALSE
    };

    g_tree_foreach(process->threads, stop_thread, &args);
}

static void linux_process_stop_all_threads(struct linux_process_info *process, const nstime_t *ts, guint32 exit_frame, gboolean soft_end)
{
    struct stop_thread_args args = {
        .mode = STOP_ALL_THREADS,
        .ts = ts,
        .exit_frame = exit_frame,
        .process = process,
        .soft_end = soft_end
    };

    g_tree_foreach(process->threads, stop_thread, &args);
}

static void linux_process_stop_all_secondary_threads(struct linux_process_info *process, const nstime_t *ts, guint32 exit_frame)
{
    struct stop_thread_args args = {
        .mode = STOP_ALL_SECONDARY_THREADS,
        .ts = ts,
        .exit_frame = exit_frame,
        .process = process,
        .soft_end = FALSE
    };

    g_tree_foreach(process->threads, stop_thread, &args);
}

struct update_tid_change_args {
    pid_t new_tid;
    pid_t old_tid;
    guint32 framenum;
    gboolean found;
};

static gboolean update_tid_change(gpointer key _U_, gpointer value, gpointer data)
{
    struct time_range_info *info = value;
    struct update_tid_change_args *args = data;

    if (info->info.thread_info.tid == args->old_tid) {
        args->found = TRUE;
        info->info.thread_info.prev_tid = args->old_tid;
        info->info.thread_info.tid = args->new_tid;
        info->info.thread_info.tid_change_frame = args->framenum;

        // return TRUE so traversal is stopped
        return TRUE;
    }

    // return FALSE so traversal isn't stopped
    return FALSE;
}

static void linux_process_change_thread_tid(struct linux_process_info *process, pid_t new_tid, pid_t old_tid, const nstime_t *ts, guint32 framenum)
{
    // no change occurred
    if (new_tid == old_tid)
        return;

    // stop thread corresponding to new TID
    linux_process_stop_thread(process, new_tid, ts, framenum);

    // make sure new TID is linked to the process
    tid_lifecycle_update(process->machine_id, new_tid, ts, process->piid, TID_LINK);

    struct update_tid_change_args args = {
        .new_tid = new_tid,
        .old_tid = old_tid,
        .framenum = framenum,
        .found = FALSE
    };
    
    // update thread corresponding to old TID
    g_tree_foreach(process->threads, update_tid_change, &args);

    // no thread corresponding to old TID - create it and update it
    if (!args.found) {
        linux_process_add_thread(process, old_tid, 0, NULL, 0);
        g_tree_foreach(process->threads, update_tid_change, &args);

        // link thread to process
        tid_lifecycle_update(process->machine_id, old_tid, ts, process->piid, TID_LINK);
    }
}

static struct linux_process_info *new_linux_process_info(guint32 machine_id, pid_t pid, const nstime_t *start_ts, guint32 start_frame, guint32 parent_piid)
{
    struct linux_process_info *process;

    // create process
    process = create_linux_process_info(machine_id);
    process->pid = pid;
    process->start_frame = start_frame;

    // add main thread
    linux_process_add_thread(process, pid, 0, start_ts, start_frame);
    
    if (parent_piid != 0)
        linux_process_set_parent(process, parent_piid, start_ts, start_frame);

    return process;
}

const struct linux_process_info *traceshark_update_linux_process_fork(guint32 machine_id, const nstime_t *ts, guint32 framenum, pid_t parent_tid, pid_t child_tid, const gchar *child_name, gboolean is_thread)
{
    struct linux_process_info *process, *child_process;
    gboolean success;
    const gchar *name;

    if (!capture_ordered_chronologically)
        return generate_anonymous_linux_process_info(parent_tid);

    // no process linked to the parent thread yet - create one
    if ((process = get_existing_linux_process_info(machine_id, parent_tid, ts, FALSE)) == NULL) {
        process = new_linux_process_info(machine_id, parent_tid, NULL, 0, 0);

        // link this thread to the created process
        tid_lifecycle_update(machine_id, parent_tid, ts, process->piid, TID_LINK);
    }
    
    // child is a thread
    if (is_thread) {
        // link the thread to the process
        tid_lifecycle_update(machine_id, child_tid, ts, process->piid, TID_START);

        // update parent process with the new thread
        linux_process_add_thread(process, child_tid, parent_tid, ts, framenum);

        // update parent process name if needed - assume parent name is the same as the child's name
        if ((name = traceshark_linux_process_get_name(process, ts)) == NULL || (strncmp(name, child_name, TASK_COMM_LEN)) != 0) {
            success = linux_process_set_name(process, child_name, NULL, 0);

            // couldn't set name with NULL ts because there is already a name
            if (!success)
                linux_process_set_name(process, child_name, ts, framenum);
        }
    }

    // child is a new process
    else {
        // create child process and link the thread to it
        child_process = new_linux_process_info(machine_id, child_tid, ts, framenum, process->piid);
        tid_lifecycle_update(machine_id, child_tid, ts, child_process->piid, TID_START);

        // update parent process with the new child
        linux_process_add_child(process, child_process->piid, ts, framenum);

        // update parent process name if needed - assume parent name is the same as the child's name
        if ((name = traceshark_linux_process_get_name(process, ts)) == NULL || (strncmp(name, child_name, TASK_COMM_LEN)) != 0) {
            success = linux_process_set_name(process, child_name, NULL, 0);

            // couldn't set name with NULL ts because there is already a name
            if (!success)
                linux_process_set_name(process, child_name, ts, framenum);
        }

        // update child process name
        linux_process_set_name(child_process, child_name, ts, framenum);
    }

    return process;
}

static const gchar *exec_file_to_name(const gchar *exec_file)
{
    int i;
    gchar *name;
    gchar **parts;

    DISSECTOR_ASSERT(exec_file != NULL && strlen(exec_file) > 0);
    
    parts = g_strsplit(exec_file, "/", 100);

    for (i = 0; i < 100, parts[i] != NULL; i++);
    name = parts[i - 1];

    name = wmem_strndup(wmem_file_scope(), name, TASK_COMM_LEN - 1);

    g_strfreev(parts);

    return name;
}

const struct linux_process_info *traceshark_update_linux_process_exec(guint32 machine_id, const nstime_t *ts, guint32 framenum, pid_t pid, const gchar *exec_file, pid_t old_tid)
{
    struct linux_process_info *process;
    const gchar *name;

    if (!capture_ordered_chronologically)
        return generate_anonymous_linux_process_info(pid);

    // no process linked to the calling thread yet - create one
    if ((process = get_existing_linux_process_info(machine_id, pid, ts, FALSE)) == NULL) {
        process = new_linux_process_info(machine_id, pid, NULL, 0, 0);

        // link this thread to the created process
        tid_lifecycle_update(machine_id, pid, ts, process->piid, TID_LINK);
    }

    // update exec file
    linux_process_set_exec_file(process, exec_file, ts, framenum);

    // update process name if needed
    if ((name = traceshark_linux_process_get_name(process, ts)) == NULL || (strncmp(name, exec_file, TASK_COMM_LEN)) != 0) {
        name = exec_file_to_name(exec_file);
        linux_process_set_name(process, name, ts, framenum);
    }

    // if the TID has changed, the new TID is the actual PID, make sure it is updated
    if (pid != old_tid)
        process->pid = pid;

    // update TID change
    linux_process_change_thread_tid(process, pid, old_tid, ts, framenum);

    // stop all secondary threads
    linux_process_stop_all_secondary_threads(process, ts, framenum);

    return process;
}

const struct linux_process_info *traceshark_update_linux_process_exit_group(guint32 machine_id, const nstime_t *ts, guint32 framenum, pid_t pid, gint32 exit_code)
{
    struct linux_process_info *process;

    if (!capture_ordered_chronologically)
        return generate_anonymous_linux_process_info(pid);

    // no process linked to the calling thread yet - create one
    if ((process = get_existing_linux_process_info(machine_id, pid, ts, FALSE)) == NULL) {
        process = new_linux_process_info(machine_id, pid, NULL, 0, 0);

        // link this thread to the created process
        tid_lifecycle_update(machine_id, pid, ts, process->piid, TID_LINK);
    }

    // stop all threads - use a soft end because this event may be followed by thread exit events,
    // and marking the threads as ended here will cause these events to not be linked to this process anymore.
    linux_process_stop_all_threads(process, ts, framenum, TRUE);

    // set exit code
    process->has_exit_code = TRUE;
    process->exit_code = exit_code;

    // set process exit frame
    process->exit_frame = framenum;

    return process;
}

const struct linux_process_info *traceshark_update_linux_process_exit(guint32 machine_id, const nstime_t *ts, guint32 framenum, pid_t pid, const gchar *name)
{
    struct linux_process_info *process;
    const gchar *current_name;
    gboolean success;

    if (!capture_ordered_chronologically)
        return generate_anonymous_linux_process_info(pid);

    // no process linked to the calling thread yet - create one
    if ((process = get_existing_linux_process_info(machine_id, pid, ts, TRUE)) == NULL)
        process = new_linux_process_info(machine_id, pid, NULL, 0, 0);
    
    // update process name if needed
    if ((current_name = traceshark_linux_process_get_name(process, ts)) == NULL || (strncmp(current_name, name, TASK_COMM_LEN)) != 0) {
        success = linux_process_set_name(process, name, NULL, 0);

        // couldn't set name with NULL ts because there is already a name
        if (!success)
            linux_process_set_name(process, name, ts, framenum);
    }

    // stop thread
    linux_process_stop_thread(process, pid, ts, framenum);

    return process;
}