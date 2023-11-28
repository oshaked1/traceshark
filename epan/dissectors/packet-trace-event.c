#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/traceshark.h>
#include <wiretap/traceshark.h>

static int proto_trace_event = -1;
static int proto_frame = -1;

static dissector_table_t event_type_dissector_table;

/**
 * Process info fields
*/
static int hf_process_piid = -1;
static int hf_process_pid_linux = -1;
static int hf_process_pid_and_name = -1;
static int hf_process_tid_linux = -1;
static int hf_process_start_frame = -1;
static int hf_process_exit_code_linux = -1;
static int hf_process_exit_frame = -1;
static int hf_process_parent_piid = -1;
static int hf_process_parent_pid_linux = -1;
static int hf_process_parent_name = -1;
static int hf_process_parent_frame = -1;
static int hf_process_name = -1;
static int hf_process_name_frame = -1;
static int hf_process_exec_file = -1;
static int hf_process_exec_frame = -1;
static int hf_process_child_piid = -1;
static int hf_process_child_pid_linux = -1;
static int hf_process_child_name = -1;
static int hf_process_child_start_frame = -1;
static int hf_process_child_exit_frame = -1;
static int hf_process_child_is_active = -1;
static int hf_process_thread_tid_linux = -1;
static int hf_process_thread_creator_tid_linux = -1;
static int hf_process_thread_prev_tid = -1;
static int hf_process_thread_tid_change_frame = -1;
static int hf_process_thread_start_frame = -1;
static int hf_process_thread_exit_frame = -1;
static int hf_process_thread_is_active = -1;

static expert_field ei_trace_event_no_process_tracking = EI_INIT;

/**
 * Additional frame fields
*/
static int hf_event_type = -1;
static int hf_machine_id = -1;
static int hf_hostname = -1;
static int hf_machine_id_and_hostname = -1;
static int hf_os_type = -1;
static int hf_os_version = -1;
static int hf_arch = -1;
static int hf_num_cpus = -1;

static gint ett_machine_info = -1;
static gint ett_process_info = -1;
static gint ett_process_parents = -1;
static gint ett_process_names = -1;
static gint ett_process_exec_files = -1;
static gint ett_process_children = -1;
static gint ett_process_child_info = -1;
static gint ett_process_threads = -1;
static gint ett_process_thread_info = -1;

static const value_string event_types[] = {
    { EVENT_TYPE_UNKNOWN, "Unknown" },
    { EVENT_TYPE_LINUX_TRACE_EVENT, "Linux Trace Event" },
    { 0, "NULL" }
};

static const value_string os_types[] = {
    { OS_UNKNOWN, "Unknown" },
    { OS_LINUX, "Linux" },
    { OS_WINDOWS, "Windows" },
    { 0, "NULL" }
};

static const value_string architectures[] = {
    { ARCH_UNKNOWN, "Unknown" },
    { ARCH_X86_32, "x86-32" },
    { ARCH_X86_64, "x86-64" },
    { 0, "NULL" }
};

static nstime_t prev_ts = NSTIME_INIT_UNSET;

struct linux_process_info_dissection_args {
    proto_tree *tree;
    tvbuff_t *tvb;
    guint32 machine_id;
    nstime_t *ts;
    guint32 framenum;
    gboolean dissect_active;
    guint active_num;
    guint inactive_num;
    pid_t current_thread;
};

static gboolean dissect_linux_process_parent(GTreeNode *node, gpointer data)
{
    GTreeNode *prev_node;
    struct time_range_info *prev_info;
    proto_item *item;
    const struct linux_process_info *parent, *prev_parent;
    const gchar *name, *prev_name;
    struct time_range_info *info = g_tree_node_value(node);
    struct linux_process_info_dissection_args *args = data;

    parent = traceshark_get_linux_process_by_piid(args->machine_id, info->info.parent_piid);
    DISSECTOR_ASSERT(parent != NULL);
    name = traceshark_linux_process_get_name(parent, &info->start_ts);
    
    // this is the first event
    if ((prev_node = g_tree_node_previous(node)) == NULL) {
        item = traceshark_proto_tree_add_uint(args->tree, hf_process_parent_frame, args->tvb, 0, 0, info->start_frame);
        proto_item_set_text(item, "Parent set to PID %d", parent->pid);

        if (name != NULL)
            proto_item_append_text(item, " (%s)", name);
        
        if (info->start_frame != 0)
            proto_item_append_text(item, " in frame %u", info->start_frame);
        else
            proto_item_append_text(item, " at an unknown time");
    }

    // this is not the first event
    else {
        prev_info = g_tree_node_value(prev_node);
        prev_parent = traceshark_get_linux_process_by_piid(args->machine_id, prev_info->info.parent_piid);
        DISSECTOR_ASSERT(prev_parent != NULL);
        prev_name = traceshark_linux_process_get_name(prev_parent, &info->start_ts);
        item = traceshark_proto_tree_add_uint(args->tree, hf_process_parent_frame, args->tvb, 0, 0, info->start_frame);
        proto_item_set_text(item, "Parent changed from PID %d", prev_parent->pid);
        
        if (prev_name != NULL)
            proto_item_append_text(item, " (%s)", prev_name);
        
        proto_item_append_text(item, "to PID %d", parent->pid);

        if (name != NULL)
            proto_item_append_text(item, " (%s)", name);
        
        proto_item_append_text(item, " in frame %u", info->start_frame);
    }

    return FALSE; // return FALSE so traversal isn't stopped
}

static void dissect_linux_process_parents(tvbuff_t *tvb, packet_info *pinfo, proto_tree *process_tree, const struct linux_process_info *process)
{
    proto_item *parents_item, *item;
    proto_tree *parents_tree;
    const struct linux_process_info *parent;
    const gchar *name;

    if ((parent = traceshark_linux_process_get_parent(process, &pinfo->abs_ts)) != NULL) {
        parents_item = traceshark_proto_tree_add_int(process_tree, hf_process_parent_pid_linux, tvb, 0, 0, parent->pid);
        proto_item_set_text(parents_item, "Parent: PID %d", parent->pid);

        item = traceshark_proto_tree_add_uint(process_tree, hf_process_parent_piid, tvb, 0, 0, parent->piid);
        proto_item_set_hidden(item);

        if ((name = traceshark_linux_process_get_name(parent, &pinfo->abs_ts)) != NULL) {
            item = traceshark_proto_tree_add_string(process_tree, hf_process_parent_name, tvb, 0, 0, name);
            proto_item_set_hidden(item);
            proto_item_append_text(parents_item, " (%s)", name);
        }
    }

    else {
        parents_item = proto_tree_add_item(process_tree, proto_trace_event, tvb, 0, 0, ENC_NA);
        proto_item_set_text(parents_item, "Parent: unknown at the time of this event");
    }

    parents_tree = proto_item_add_subtree(parents_item, ett_process_parents);

    struct linux_process_info_dissection_args args = {
        .tree = parents_tree,
        .tvb = tvb,
        .machine_id = process->machine_id
    };

    g_tree_foreach_node(process->parent_piid, dissect_linux_process_parent, &args);
}

static gboolean dissect_linux_process_name(GTreeNode *node, gpointer data)
{
    GTreeNode *prev_node;
    struct time_range_info *prev_info;
    proto_item *item;
    struct time_range_info *info = g_tree_node_value(node);
    struct linux_process_info_dissection_args *args = data;
    
    // this is the first event
    if ((prev_node = g_tree_node_previous(node)) == NULL) {
        item = traceshark_proto_tree_add_uint(args->tree, hf_process_name_frame, args->tvb, 0, 0, info->start_frame);
        proto_item_set_text(item, "Name set to %s", info->info.name);
        
        if (info->start_frame != 0)
            proto_item_append_text(item, " in frame %u", info->start_frame);
        else
            proto_item_append_text(item, " at an unknown time");
    }

    // this is not the first event
    else {
        prev_info = g_tree_node_value(prev_node);
        item = traceshark_proto_tree_add_uint(args->tree, hf_process_name_frame, args->tvb, 0, 0, info->start_frame);
        proto_item_set_text(item, "Name changed from %s to %s in frame %u", prev_info->info.name, info->info.name, info->start_frame);
    }

    return FALSE; // return FALSE so traversal isn't stopped
}

static void dissect_linux_process_names(tvbuff_t *tvb, packet_info *pinfo, proto_tree *process_tree, const struct linux_process_info *process)
{
    proto_item *names_item;
    proto_tree *names_tree;
    const gchar *name;

    if ((name = traceshark_linux_process_get_name(process, &pinfo->abs_ts)) != NULL) {
        names_item = traceshark_proto_tree_add_string(process_tree, hf_process_name, tvb, 0, 0, name);
        proto_item_set_text(names_item, "Name: %s", name);
    }

    else {
        names_item = proto_tree_add_item(process_tree, proto_trace_event, tvb, 0, 0, ENC_NA);
        proto_item_set_text(names_item, "Name: unknown at the time of this event");
    }
    
    names_tree = proto_item_add_subtree(names_item, ett_process_names);

    struct linux_process_info_dissection_args args = {
        .tree = names_tree,
        .tvb = tvb
    };

    g_tree_foreach_node(process->name, dissect_linux_process_name, &args);
}

static gboolean dissect_linux_process_exec_file(GTreeNode *node, gpointer data)
{
    GTreeNode *prev_node;
    struct time_range_info *prev_info;
    proto_item *item;
    struct time_range_info *info = g_tree_node_value(node);
    struct linux_process_info_dissection_args *args = data;
    
    // this is the first event
    if ((prev_node = g_tree_node_previous(node)) == NULL) {
        item = traceshark_proto_tree_add_uint(args->tree, hf_process_exec_frame, args->tvb, 0, 0, info->start_frame);
        proto_item_set_text(item, "Exec file set to %s", info->info.exec_file);
        
        if (info->start_frame != 0)
            proto_item_append_text(item, " in frame %u", info->start_frame);
        else
            proto_item_append_text(item, " at an unknown time");
    }

    // this is not the first event
    else {
        prev_info = g_tree_node_value(prev_node);
        item = traceshark_proto_tree_add_uint(args->tree, hf_process_exec_frame, args->tvb, 0, 0, info->start_frame);
        proto_item_set_text(item, "Exec file changed from %s to %s in frame %u", prev_info->info.exec_file, info->info.exec_file, info->start_frame);
    }

    return FALSE; // return FALSE so traversal isn't stopped
}

static void dissect_linux_process_exec_files(tvbuff_t *tvb, packet_info *pinfo, proto_tree *process_tree, const struct linux_process_info *process)
{
    proto_item *exec_files_item;
    proto_tree *exec_files_tree;
    const gchar *exec_file;

    if ((exec_file = traceshark_linux_process_get_exec_file(process, &pinfo->abs_ts)) != NULL) {
        exec_files_item = traceshark_proto_tree_add_string(process_tree, hf_process_exec_file, tvb, 0, 0, exec_file);
        proto_item_set_text(exec_files_item, "Exec File: %s", exec_file);
    }

    else {
        exec_files_item = proto_tree_add_item(process_tree, proto_trace_event, tvb, 0, 0, ENC_NA);
        proto_item_set_text(exec_files_item, "Exec File: unknown at the time of this event");
    }
    
    exec_files_tree = proto_item_add_subtree(exec_files_item, ett_process_exec_files);

    struct linux_process_info_dissection_args args = {
        .tree = exec_files_tree,
        .tvb = tvb
    };

    g_tree_foreach_node(process->exec_file, dissect_linux_process_exec_file, &args);
}

static gboolean dissect_linux_process_child(gpointer key _U_, gpointer value, gpointer data)
{
    proto_item *child_item, *item;
    proto_tree *child_tree;
    gchar *state;
    const gchar *name;
    const struct linux_process_info *child;
    gboolean ret = FALSE; // return FALSE so traversal isn't stopped
    struct time_range_info *info = value;
    struct linux_process_info_dissection_args *args = data;

    // active child
    if (nstime_cmp(&info->start_ts, args->ts) <= 0 && (nstime_is_unset(&info->end_ts) || nstime_cmp(args->ts, &info->end_ts) <= 0)) {
        if (!args->dissect_active)
            return ret;
        
        args->active_num++;
        state = "active";
    }

    // inactive child
    else {
        if (args->dissect_active)
            return ret;
        
        args->inactive_num++;

        if (nstime_cmp(args->ts, &info->start_ts) < 0)
            state = "not yet started";
        else
            state = "already exited";
    }

    // add child tree
    child_item = proto_tree_add_item(args->tree, proto_trace_event, args->tvb, 0, 0, ENC_NA);
    child_tree = proto_item_add_subtree(child_item, ett_process_child_info);

    // add PIID
    item = proto_tree_add_uint(child_tree, hf_process_child_piid, args->tvb, 0, 0, info->info.child_piid);
    proto_item_set_generated(item);

    // add start frame
    if (info->start_frame != 0)
        proto_tree_add_uint(child_tree, hf_process_child_start_frame, args->tvb, 0, 0, info->start_frame);

    // add PID
    child = traceshark_get_linux_process_by_piid(args->machine_id, info->info.child_piid);
    DISSECTOR_ASSERT(child != NULL);
    proto_tree_add_int(child_tree, hf_process_child_pid_linux, args->tvb, 0, 0, child->pid);
    proto_item_set_text(child_item, "PID %d", child->pid);

    // add name
    name = traceshark_linux_process_get_name(child, args->ts);
    if (name != NULL) {
        proto_tree_add_string(child_tree, hf_process_child_name, args->tvb, 0, 0, name);
        proto_item_append_text(child_item, " (%s)", name);
    }
    
    // add exit frame
    if (info->end_frame != 0)
        proto_tree_add_uint(child_tree, hf_process_child_exit_frame, args->tvb, 0, 0, info->end_frame);
    
    // add active
    item = proto_tree_add_boolean(child_tree, hf_process_child_is_active, args->tvb, 0, 0, args->dissect_active);
    proto_item_set_generated(item);

    proto_item_append_text(child_item, " (%s)", state);

    return ret;
}

static void dissect_linux_process_children(tvbuff_t *tvb, packet_info *pinfo, proto_tree *process_tree, const struct linux_process_info *process)
{
    proto_item *children_item;
    proto_tree *children_tree;

    children_item = proto_tree_add_item(process_tree, proto_trace_event, tvb, 0, 0, ENC_NA);
    proto_item_set_text(children_item, "Children");
    children_tree = proto_item_add_subtree(children_item, ett_process_children);
    
    struct linux_process_info_dissection_args args = {
        .tree = children_tree,
        .tvb = tvb,
        .machine_id = process->machine_id,
        .ts = &pinfo->abs_ts,
        .dissect_active = TRUE,
        .active_num = 0,
        .inactive_num = 0
    };

    g_tree_foreach(process->children, dissect_linux_process_child, &args);

    args.dissect_active = FALSE;
    g_tree_foreach(process->children, dissect_linux_process_child, &args);

    proto_item_append_text(children_item, ": %u active, %u inactive", args.active_num, args.inactive_num);
}

static gboolean dissect_linux_process_thread(gpointer key _U_, gpointer value, gpointer data)
{
    proto_item *thread_item, *item;
    proto_tree *thread_tree;
    gchar *state;
    pid_t tid;
    gboolean ret = FALSE; // return FALSE so traversal isn't stopped
    struct time_range_info *info = value;
    struct linux_process_info_dissection_args *args = data;

    // active thread
    if (nstime_cmp(&info->start_ts, args->ts) <= 0 && (nstime_is_unset(&info->end_ts) || nstime_cmp(args->ts, &info->end_ts) < 0)) {
        if (!args->dissect_active)
            return ret;
        
        args->active_num++;
        state = "active";
    }

    // inactive thread
    else {
        if (args->dissect_active)
            return ret;
        
        args->inactive_num++;

        if (nstime_cmp(args->ts, &info->start_ts) < 0)
            state = "not yet started";
        else
            state = "already exited";
    }

    // current thread
    if (args->dissect_active && info->info.thread_info.tid == args->current_thread) {
        // make sure the thread didn't have a different TID at the time of this event
        if (args->framenum >= info->info.thread_info.tid_change_frame)
            state = "current thread";
    }

    // if the TID of this thread has changed but not yet at the time of this event, use the old TID
    if (args->framenum < info->info.thread_info.tid_change_frame)
        tid = info->info.thread_info.prev_tid;
    else
        tid = info->info.thread_info.tid;

    // add thread tree
    thread_item = proto_tree_add_item(args->tree, proto_trace_event, args->tvb, 0, 0, ENC_NA);
    proto_item_set_text(thread_item, "TID %d (%s)", tid, state);
    thread_tree = proto_item_add_subtree(thread_item, ett_process_thread_info);

    // add start frame
    if (info->start_frame != 0)
        proto_tree_add_uint(thread_tree, hf_process_thread_start_frame, args->tvb, 0, 0, info->start_frame);
    
    // add TID
    proto_tree_add_int(thread_tree, hf_process_thread_tid_linux, args->tvb, 0, 0, tid);

    // add creator TID
    if (info->info.thread_info.creator_tid != 0)
        proto_tree_add_int(thread_tree, hf_process_thread_creator_tid_linux, args->tvb, 0, 0, info->info.thread_info.creator_tid);

    // add previous TID and TID change frame
    if (info->info.thread_info.tid_change_frame != 0 && info->info.thread_info.tid_change_frame <= args->framenum) {
        proto_tree_add_int(thread_tree, hf_process_thread_prev_tid, args->tvb, 0, 0, info->info.thread_info.prev_tid);
        proto_tree_add_uint(thread_tree, hf_process_thread_tid_change_frame, args->tvb, 0, 0, info->info.thread_info.tid_change_frame);
    }
    
    // add exit frame
    if (info->end_frame != 0)
        proto_tree_add_uint(thread_tree, hf_process_thread_exit_frame, args->tvb, 0, 0, info->end_frame);
    
    // add active
    item = proto_tree_add_boolean(thread_tree, hf_process_thread_is_active, args->tvb, 0, 0, args->dissect_active);
    proto_item_set_generated(item);

    return ret;
}

static void dissect_linux_process_threads(tvbuff_t *tvb, packet_info *pinfo, proto_tree *process_tree, const struct linux_process_info *process, pid_t tid)
{
    proto_item *threads_item;
    proto_tree *threads_tree;

    threads_item = proto_tree_add_item(process_tree, proto_trace_event, tvb, 0, 0, ENC_NA);
    proto_item_set_text(threads_item, "Threads");
    threads_tree = proto_item_add_subtree(threads_item, ett_process_threads);

    struct linux_process_info_dissection_args args = {
        .tree = threads_tree,
        .tvb = tvb,
        .ts = &pinfo->abs_ts,
        .framenum = pinfo->num,
        .dissect_active = TRUE,
        .active_num = 0,
        .inactive_num = 0,
        .current_thread = tid
    };

    g_tree_foreach(process->threads, dissect_linux_process_thread, &args);
    
    args.dissect_active = FALSE;
    g_tree_foreach(process->threads, dissect_linux_process_thread, &args);

    proto_item_append_text(threads_item, ": %u active, %u inactive", args.active_num, args.inactive_num);
}

static void dissect_linux_process_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *process_tree, proto_item *process_item, pid_t tid, const struct linux_process_info *process)
{
    proto_item *item;
    const gchar *name;
    gchar *pid_and_name;

    // add PIID
    item = proto_tree_add_uint(process_tree, hf_process_piid, tvb, 0, 0, process->piid);
    proto_item_set_generated(item);

    // anonymous PIID - clarify this
    if (process->piid == 0)
        proto_item_append_text(item, " (anonymous process)");

    // add PID
    proto_tree_add_int(process_tree, hf_process_pid_linux, tvb, 0, 0, process->pid);
    proto_item_append_text(process_item, ": PID = %d", process->pid);

    // add PID and name
    pid_and_name = wmem_strdup_printf(pinfo->pool, "%d", process->pid);
    if ((name = traceshark_linux_process_get_name(process, &pinfo->abs_ts)) != NULL)
        pid_and_name = wmem_strdup_printf(pinfo->pool, "%s (%s)", pid_and_name, name);
    item = proto_tree_add_string(process_tree, hf_process_pid_and_name, tvb, 0, 0, pid_and_name);
    proto_item_set_hidden(item);

    // add TID
    proto_tree_add_int(process_tree, hf_process_tid_linux, tvb, 0, 0, tid);

    // add start frame
    if (process->start_frame != 0)
        proto_tree_add_uint(process_tree, hf_process_start_frame, tvb, 0, 0, process->start_frame);
    
    // add exit code
    if (process->has_exit_code)
        proto_tree_add_int(process_tree, hf_process_exit_code_linux, tvb, 0, 0, process->exit_code);
    
    // add exit frame
    if (process->exit_frame != 0)
        proto_tree_add_uint(process_tree, hf_process_exit_frame, tvb, 0, 0, process->exit_frame);
    
    // add parents
    if (process->parent_piid && g_tree_nnodes(process->parent_piid) > 0)
        dissect_linux_process_parents(tvb, pinfo, process_tree, process);
    
    // add names
    if (process->name && g_tree_nnodes(process->name) > 0)
        dissect_linux_process_names(tvb, pinfo, process_tree, process);
    
    // add exec files
    if (process->exec_file && g_tree_nnodes(process->exec_file) > 0)
        dissect_linux_process_exec_files(tvb, pinfo, process_tree, process);
    
    // add children
    if (process->children && g_tree_nnodes(process->children) > 0)
        dissect_linux_process_children(tvb, pinfo, process_tree, process);
    
    // add threads
    if (process->threads && g_tree_nnodes(process->threads) > 0)
        dissect_linux_process_threads(tvb, pinfo, process_tree, process, tid);
}

static void dissect_process_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct traceshark_dissector_data *dissector_data)
{
    proto_item *item, *process_item;
    proto_tree *process_tree;

    // create process tree
    process_item = proto_tree_add_item(tree, proto_trace_event, tvb, 0, 0, ENC_NA);
    proto_item_set_text(process_item, "Process Info");
    process_tree = proto_item_add_subtree(process_item, ett_process_info);

    // make sure capture is ordered chronologically
    if (!capture_ordered_chronologically) {
        proto_item_append_text(process_item, " (not tracked)");
        item = proto_tree_add_expert(process_tree, pinfo, &ei_trace_event_no_process_tracking, tvb, 0, 0);
        proto_item_append_text(item, ": capture isn't ordered chronologically (sort using the reordercap utility)");
    }

    // dissect process info based on OS
    switch (dissector_data->event_type) {
        case EVENT_TYPE_LINUX_TRACE_EVENT:
            dissect_linux_process_info(tvb, pinfo, process_tree, process_item, dissector_data->pid.linux, dissector_data->process_info.linux);
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }
}

static int dissect_trace_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *machine_info_item, *item;
    proto_tree *frame_tree, *machine_info_tree;
    struct event_options *metadata;
    struct traceshark_dissector_data *dissector_data;
    const struct traceshark_machine_info *machine_info;
    dissector_handle_t event_type_dissector;
    int ret;
    
    DISSECTOR_ASSERT_HINT(pinfo->rec->rec_type == REC_TYPE_FT_SPECIFIC_EVENT, "Expected REC_TYPE_FT_SPECIFIC_EVENT record");
    metadata = (struct event_options *)ws_buffer_start_ptr(&pinfo->rec->options_buf);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TRACE_EVENT");
    col_add_fstr(pinfo->cinfo, COL_INFO, "Machine ID = %u, Event Type = %u", metadata->machine_id, metadata->event_type);

    // add fields to frame tree
    frame_tree = proto_find_subtree(tree, proto_frame);
    traceshark_proto_tree_add_uint(frame_tree, hf_event_type, tvb, 0, 0, metadata->event_type);

    // create machine info tree inside frame tree
    machine_info_tree = proto_tree_add_subtree(frame_tree, tvb, 0, 0, ett_machine_info, &machine_info_item, "Machine Info");
    proto_item_append_text(machine_info_item, " (ID: %u)", metadata->machine_id);

    traceshark_proto_tree_add_uint(machine_info_tree, hf_machine_id, tvb, 0, 0, metadata->machine_id);

    // fetch machine info and add fields
    machine_info = epan_get_machine_info(pinfo->epan, metadata->machine_id);
    DISSECTOR_ASSERT_HINT(machine_info != NULL, "Couldn't fetch machine info");

    if (machine_info->hostname != NULL) {
        traceshark_proto_tree_add_string(machine_info_tree, hf_hostname, tvb, 0, 0, machine_info->hostname);
        item = traceshark_proto_tree_add_string(machine_info_tree, hf_machine_id_and_hostname, tvb, 0, 0, wmem_strdup_printf(pinfo->pool, "%s (%u)", machine_info->hostname, metadata->machine_id));
    }
    else
        item = traceshark_proto_tree_add_string(machine_info_tree, hf_machine_id_and_hostname, tvb, 0, 0, wmem_strdup_printf(pinfo->pool, "%u", metadata->machine_id));
    
    proto_item_set_hidden(item);
    
    traceshark_proto_tree_add_uint(machine_info_tree, hf_os_type, tvb, 0, 0, machine_info->os_type);

    if (machine_info->os_version != NULL)
        traceshark_proto_tree_add_string(machine_info_tree, hf_os_version, tvb, 0, 0, machine_info->os_version);
    
    traceshark_proto_tree_add_uint(machine_info_tree, hf_arch, tvb, 0, 0, machine_info->arch);

    if (machine_info->num_cpus > 0)
        traceshark_proto_tree_add_uint(machine_info_tree, hf_num_cpus, tvb, 0, 0, machine_info->num_cpus);
    
    // make sure this frame follows the previous one chronologically
    if (!pinfo->fd->visited) {
        if (capture_ordered_chronologically && nstime_cmp(&pinfo->abs_ts, &prev_ts) < 0)
            capture_ordered_chronologically = FALSE;
    
        else
            nstime_copy(&prev_ts, &pinfo->abs_ts);
    }

    // get dissector for this event type
    if ((event_type_dissector = dissector_get_uint_handle(event_type_dissector_table, metadata->event_type)) == NULL)
        return 0;
    
    // initialize dissector data to be passed to next dissector
    dissector_data = wmem_new0(pinfo->pool, struct traceshark_dissector_data);
    dissector_data->machine_id = metadata->machine_id;
    dissector_data->event_type = metadata->event_type;
    
    ret = call_dissector_only(event_type_dissector, tvb, pinfo, tree, dissector_data);

    // if higher level dissector added process info, dissect it
    if (dissector_data->process_info.raw_ptr != NULL)
        dissect_process_info(tvb, pinfo, tree, dissector_data);
    
    return ret;
}

static gboolean reset_chronological_tracking(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data _U_)
{
    nstime_set_unset(&prev_ts);
    capture_ordered_chronologically = TRUE;

    // return TRUE so this callback isn't unregistered
    return TRUE;
}

void proto_register_trace_event(void)
{
    expert_module_t *expert_trace_event;

    static hf_register_info hf[] = {
        { &hf_process_piid,
          { "PIID", "process.piid",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Process instance ID (generated by traceshark)", HFILL }
        },
        { &hf_process_pid_linux,
          { "PID", "process.pid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Process ID (sometimes referred to as TGID on Linux)", HFILL }
        },
        { &hf_process_pid_and_name,
          { "PID and Name", "process.pid_and_name",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Process ID and name", HFILL }
        },
        { &hf_process_tid_linux,
          { "TID", "process.tid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Thread ID (sometimes referred to as PID on Linux)", HFILL }
        },
        { &hf_process_start_frame,
          { "Started in", "process.start_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "Process start frame", HFILL }
        },
        { &hf_process_exit_code_linux,
          { "Exit Code", "process.exit_code",
            FT_INT32, BASE_DEC, NULL, 0,
            "Process exit code", HFILL }
        },
        { &hf_process_exit_frame,
          { "Exited in", "process.exit_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "Process exit frame", HFILL }
        },
        { &hf_process_parent_piid,
          { "Parent PIID", "process.parent.piid",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Parent process instance ID (generated by traceshark)", HFILL }
        },
        { &hf_process_parent_pid_linux,
          { "Parent PID", "process.parent.pid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Parent process ID (sometimes referred to as TGID on Linux)", HFILL }
        },
        { &hf_process_parent_name,
          { "Parent name", "process.parent.name",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Parent name", HFILL }
        },
        { &hf_process_parent_frame,
          { "Parent set in", "process.parent.frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "Frame in which the process' parent has been set", HFILL }
        },
        { &hf_process_name,
          { "Name", "process.name",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Process name", HFILL }
        },
        { &hf_process_name_frame,
          { "Named in", "process.name.frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "Frame in which the process name has been set", HFILL }
        },
        { &hf_process_exec_file,
          { "Exec File", "process.exec_file",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Process executable file", HFILL }
        },
        { &hf_process_exec_frame,
          { "Exec file set in", "process.exec_file.frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "Frame in which the process' exec file has been set", HFILL }
        },
        { &hf_process_child_piid,
          { "PIID", "process.child.piid",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Child process instance ID (generated by traceshark)", HFILL }
        },
        { &hf_process_child_pid_linux,
          { "PID", "process.child.pid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Child process ID (sometimes referred to as TGID on Linux)", HFILL }
        },
        { &hf_process_child_name,
          { "Child name", "process.child.name",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Child name (at the time of this event)", HFILL }
        },
        { &hf_process_child_start_frame,
          { "Started in", "process.child.start_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "Child start frame", HFILL }
        },
        { &hf_process_child_exit_frame,
          { "Exited in", "process.child.exit_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "Child exit frame", HFILL }
        },
        { &hf_process_child_is_active,
          { "Active", "process.child.is_active",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            "Child is alive at the time of this event", HFILL }
        },
        { &hf_process_thread_tid_linux,
          { "TID", "process.thread.tid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Thread ID", HFILL }
        },
        { &hf_process_thread_creator_tid_linux,
          { "Creator TID", "process.thread.creator_tid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Creator thread ID", HFILL }
        },
        { &hf_process_thread_prev_tid,
          { "Previous TID", "process.thread.prev_tid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Previous TID (on Linux, when a secondary thread calls exec, it inherits the TID of the main thread)", HFILL }
        },
        { &hf_process_thread_tid_change_frame,
          { "TID changed in", "process.thread.tid_change_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "Thread ID change frame (on Linux, when a secondary thread calls exec, it inherits the TID of the main thread)", HFILL }
        },
        { &hf_process_thread_start_frame,
          { "Started in", "process.thread.start_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "Thread start frame", HFILL }
        },
        { &hf_process_thread_exit_frame,
          { "Exited in", "process.thread.exit_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "Thread exit frame", HFILL }
        },
        { &hf_process_thread_is_active,
          { "Active", "process.thread.is_active",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            "Thread is active at the time of this event", HFILL }
        }
    };
    
    static hf_register_info frame_hf[] = {
        { &hf_event_type,
          { "Event Type", "frame.event_type",
            FT_UINT16, BASE_DEC, VALS(event_types), 0,
            "The type of trace event", HFILL }
        },
        { &hf_machine_id,
          { "Machine ID", "frame.machine.id",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Machine ID as present in the trace file", HFILL }
        },
        { &hf_hostname,
          { "Hostname", "frame.machine.hostname",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Machine hostname", HFILL }
        },
        { &hf_machine_id_and_hostname,
          { "ID and Hostname", "frame.machine.id_hostname",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Machine ID and hostname", HFILL }
        },
        { &hf_os_type,
          { "OS Type", "frame.machine.os_type",
            FT_UINT16, BASE_DEC, VALS(os_types), 0,
            "Machine operating system", HFILL }
        },
        { &hf_os_version,
          { "OS Version", "frame.machine.os_version",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Machine operating system version", HFILL }
        },
        { &hf_arch,
          { "Architecture", "frame.machine.arch",
            FT_UINT16, BASE_DEC, VALS(architectures), 0,
            "Machine architecture", HFILL }
        },
        { &hf_num_cpus,
          { "CPUs", "frame.machine.num_cpus",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Number of CPUs", HFILL }
        }
    };

    static gint *ett[] = {
        &ett_machine_info,
        &ett_process_info,
        &ett_process_parents,
        &ett_process_names,
        &ett_process_exec_files,
        &ett_process_children,
        &ett_process_child_info,
        &ett_process_threads,
        &ett_process_thread_info
    };

    static ei_register_info ei[] = {
        { &ei_trace_event_no_process_tracking,
          { "process.no_tracking", PI_ASSUMPTION, PI_WARN,
            "No process tracking performed", EXPFILL }
        }
    };

    proto_trace_event = proto_register_protocol("Trace Event", "TRACE_EVENT", "event");
    proto_register_field_array(proto_trace_event, hf, array_length(hf));

    proto_frame = proto_get_id_by_filter_name("frame");
    proto_register_field_array(proto_frame, frame_hf, array_length(frame_hf));

    proto_register_subtree_array(ett, array_length(ett));

    expert_trace_event = expert_register_protocol(proto_trace_event);
    expert_register_field_array(expert_trace_event, ei, array_length(ei));

    event_type_dissector_table = register_dissector_table("frame.event_type", "Trace Event Type", proto_trace_event, FT_UINT16, BASE_DEC);

    // register a wmem file scope trigger to reset the capture chronological order tracking
    wmem_register_callback(wmem_file_scope(), reset_chronological_tracking, NULL);
}

void proto_reg_handoff_trace_event(void)
{
    dissector_handle_t trace_event_handle;

    trace_event_handle = create_dissector_handle(dissect_trace_event, proto_trace_event);
    
    // register to wtap_fts_rec dissector table for all supported trace file types
    dissector_add_uint("wtap_fts_rec", tracecmd_get_file_type_subtype(), trace_event_handle);

    // register to pcapng block type dissector table
    dissector_add_uint("pcapng.block_type", BLOCK_TYPE_EVENT, trace_event_handle);
}