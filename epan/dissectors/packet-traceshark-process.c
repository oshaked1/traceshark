#include <epan/packet.h>
#include <epan/traceshark.h>
#include <wiretap/traceshark.h>

#define CLONE_THREAD 0x00010000

static int proto_process = -1;

static int hf_event = -1;
static int hf_is_thread_event = -1;
static int hf_creator_pid_linux = -1;
static int hf_creator_tid = -1;
static int hf_child_pid_linux = -1;
static int hf_child_tid = -1;
static int hf_child_name = -1;
static int hf_clone_flags = -1;
static int hf_clone_flags_csignal = -1;
static int hf_clone_flags_clone_vm = -1;
static int hf_clone_flags_clone_fs = -1;
static int hf_clone_flags_clone_files = -1;
static int hf_clone_flags_clone_sighand = -1;
static int hf_clone_flags_clone_pidfd = -1;
static int hf_clone_flags_clone_ptrace = -1;
static int hf_clone_flags_clone_vfork = -1;
static int hf_clone_flags_clone_parent = -1;
static int hf_clone_flags_clone_thread = -1;
static int hf_clone_flags_clone_newns = -1;
static int hf_clone_flags_clone_sysvsem = -1;
static int hf_clone_flags_clone_settls = -1;
static int hf_clone_flags_clone_parent_settid = -1;
static int hf_clone_flags_clone_child_cleartid = -1;
static int hf_clone_flags_clone_detached = -1;
static int hf_clone_flags_clone_untraced = -1;
static int hf_clone_flags_clone_child_settid = -1;
static int hf_clone_flags_clone_newcgroup = -1;
static int hf_clone_flags_clone_newuts = -1;
static int hf_clone_flags_clone_newipc = -1;
static int hf_clone_flags_clone_newuser = -1;
static int hf_clone_flags_clone_newpid = -1;
static int hf_clone_flags_clone_newnet = -1;
static int hf_clone_flags_clone_io = -1;
static int hf_clone_flags_clone_clear_sighand = -1;
static int hf_clone_flags_clone_into_cgroup = -1;
static int hf_clone_flags_clone_newtime = -1;
static int hf_old_tid_linux = -1;
static int hf_exec_file = -1;
static int hf_exit_code_linux = -1;

static gint ett_process = -1;
static gint ett_clone_flags = -1;

static const value_string process_events[] = {
    { PROCESS_FORK, "Fork" },
    { PROCESS_EXEC, "Exec" },
    { PROCESS_EXIT, "Exit" },
    { 0, "NULL" }
};

static const true_false_string tfs_generic = { "True", "False" };

static void dissect_common_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree **process_event_item, proto_item **process_event_tree, struct traceshark_dissector_data *dissector_data, enum process_event_type event, gboolean is_thread_event)
{
    proto_item *item;
    const gchar *event_str;
    const gchar *name;
    gboolean added_name = FALSE;

    *process_event_item = proto_tree_add_item(tree, proto_process, tvb, 0, 0, ENC_NA);
    *process_event_tree = proto_item_add_subtree(*process_event_item, ett_process);

    item = traceshark_proto_tree_add_boolean(*process_event_tree, hf_is_thread_event, tvb, 0, 0, is_thread_event);
    proto_item_set_hidden(item);

    if (is_thread_event) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "THREAD");
        col_set_str(pinfo->cinfo, COL_INFO, "Thread");
        proto_item_append_text(*process_event_item, ": %s", "Thread");
    }
    else {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "PROCESS");
        col_set_str(pinfo->cinfo, COL_INFO, "Process");
        proto_item_append_text(*process_event_item, ": %s", "Process");
    }

    event_str = try_val_to_str(event, process_events);
    DISSECTOR_ASSERT(event_str != NULL);
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", event_str);
    proto_item_append_text(*process_event_item, " %s", event_str);
    traceshark_proto_tree_add_string(*process_event_tree, hf_event, tvb, 0, 0, event_str);

    // add PID according to its type
    switch (dissector_data->event_type) {
        case EVENT_TYPE_LINUX_TRACE_EVENT:
            col_append_fstr(pinfo->cinfo, COL_INFO, ": %s %d", is_thread_event ? "TID" : "PID", is_thread_event ? dissector_data->pid.linux : dissector_data->process_info.linux->pid);
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }

    // add process name
    if ((name = traceshark_linux_process_get_name(dissector_data->process_info.linux, &pinfo->abs_ts)) != NULL) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s", name);
        added_name = TRUE;
    }

    // add the PID if it's a thread event
    if (is_thread_event) {
        if (added_name)
            col_append_fstr(pinfo->cinfo, COL_INFO, ", PID %d", dissector_data->process_info.linux->pid);
        else
            col_append_fstr(pinfo->cinfo, COL_INFO, " (PID %d)", dissector_data->process_info.linux->pid);
    }
    
    // if it's a process event, add the TID only if it's not the main thread
    else if (dissector_data->pid.linux != dissector_data->process_info.linux->pid) {
        if (added_name)
            col_append_fstr(pinfo->cinfo, COL_INFO, ", TID %d", dissector_data->pid.linux);
        else
            col_append_fstr(pinfo->cinfo, COL_INFO, " (TID %d)", dissector_data->pid.linux);
    }

    if (added_name)
        col_append_str(pinfo->cinfo, COL_INFO, ")");
}

static void dissect_linux_clone_flags(tvbuff_t *tvb, proto_tree *tree, guint64 clone_flags)
{
    static int * const flags[] = {
		&hf_clone_flags_csignal,
		&hf_clone_flags_clone_vm,
        &hf_clone_flags_clone_fs,
        &hf_clone_flags_clone_files,
        &hf_clone_flags_clone_sighand,
        &hf_clone_flags_clone_pidfd,
        &hf_clone_flags_clone_ptrace,
        &hf_clone_flags_clone_vfork,
        &hf_clone_flags_clone_parent,
        &hf_clone_flags_clone_thread,
        &hf_clone_flags_clone_newns,
        &hf_clone_flags_clone_sysvsem,
        &hf_clone_flags_clone_settls,
        &hf_clone_flags_clone_parent_settid,
        &hf_clone_flags_clone_child_cleartid,
        &hf_clone_flags_clone_detached,
        &hf_clone_flags_clone_untraced,
        &hf_clone_flags_clone_child_settid,
        &hf_clone_flags_clone_newcgroup,
        &hf_clone_flags_clone_newuts,
        &hf_clone_flags_clone_newipc,
        &hf_clone_flags_clone_newuser,
        &hf_clone_flags_clone_newpid,
        &hf_clone_flags_clone_newnet,
        &hf_clone_flags_clone_io,
        &hf_clone_flags_clone_clear_sighand,
        &hf_clone_flags_clone_into_cgroup,
        &hf_clone_flags_clone_newtime,
		NULL
	};

	proto_tree_add_bitmask_value(tree, tvb, 0, hf_clone_flags, ett_clone_flags, flags, clone_flags);
}

static int dissect_linux_process_fork(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct traceshark_dissector_data *dissector_data = (struct traceshark_dissector_data *)data;
    proto_item *process_event_item = NULL;
    proto_tree *process_event_tree = NULL;
    fvalue_t *fv;
    pid_t child_pid;
    const gchar *child_name;
    guint64 clone_flags;
    gboolean is_thread;

    // get child PID
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.task.task_newtask.pid");
    child_pid = fvalue_get_sinteger(fv);

    // get child name
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.task.task_newtask.comm");
    child_name = wmem_strbuf_get_str(fvalue_get_strbuf(fv));

    // get clone flags
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.task.task_newtask.clone_flags");
    switch (fvalue_type_ftenum(fv)) {
        case FT_UINT32:
            clone_flags = (guint64)fvalue_get_uinteger(fv);
            break;
        case FT_UINT64:
            clone_flags = fvalue_get_uinteger64(fv);
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }
    is_thread = clone_flags & CLONE_THREAD;

    // update process tracking with this event
    if (capture_ordered_chronologically && !pinfo->fd->visited)
        dissector_data->process_info.linux = traceshark_update_linux_process_fork(dissector_data->machine_id, &pinfo->abs_ts, pinfo->num, dissector_data->pid.linux, child_pid, child_name, is_thread);

    dissect_common_info(tvb, pinfo, tree, &process_event_item, &process_event_tree, dissector_data, PROCESS_FORK, is_thread);

    traceshark_proto_tree_add_int(process_event_tree, hf_creator_pid_linux, tvb, 0, 0, dissector_data->process_info.linux->pid);
    traceshark_proto_tree_add_int(process_event_tree, hf_creator_tid, tvb, 0, 0, dissector_data->pid.linux);
    traceshark_proto_tree_add_int(process_event_tree, hf_child_pid_linux, tvb, 0, 0, is_thread ? dissector_data->process_info.linux->pid : child_pid);
    traceshark_proto_tree_add_int(process_event_tree, hf_child_tid, tvb, 0, 0, child_pid);
    traceshark_proto_tree_add_string(process_event_tree, hf_child_name, tvb, 0, 0, child_name);
    col_append_fstr(pinfo->cinfo, COL_INFO, " has spawned a new %s with %s %d", is_thread ? "thread" : "process", is_thread ? "TID" : "PID", child_pid);
    dissect_linux_clone_flags(tvb, process_event_tree, clone_flags);
    proto_item_append_text(process_event_item, " (%d -> %d)", dissector_data->process_info.linux->pid, child_pid);

    return 0;
}

static int dissect_linux_process_exec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct traceshark_dissector_data *dissector_data = (struct traceshark_dissector_data *)data;
    proto_item *process_event_item = NULL;
    proto_tree *process_event_tree = NULL;
    fvalue_t *fv;
    const gchar *exec_file;
    pid_t old_tid;

    // get exec file
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.sched.sched_process_exec.filename");
    exec_file = wmem_strbuf_get_str(fvalue_get_strbuf(fv));

    // get old TID
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.sched.sched_process_exec.old_pid");
    old_tid = fvalue_get_sinteger(fv);

    // update process tracking with this event
    if (capture_ordered_chronologically && !pinfo->fd->visited)
        dissector_data->process_info.linux = traceshark_update_linux_process_exec(dissector_data->machine_id, &pinfo->abs_ts, pinfo->num, dissector_data->pid.linux, exec_file, old_tid);

    dissect_common_info(tvb, pinfo, tree, &process_event_item, &process_event_tree, dissector_data, PROCESS_EXEC, FALSE);

    traceshark_proto_tree_add_string(process_event_tree, hf_exec_file, tvb, 0, 0, exec_file);
    col_append_fstr(pinfo->cinfo, COL_INFO, " is executing %s", exec_file);
    proto_item_append_text(process_event_item, " (%s)", exec_file);
    traceshark_proto_tree_add_int(process_event_tree, hf_old_tid_linux, tvb, 0, 0, old_tid);

    if (old_tid != dissector_data->pid.linux)
        col_append_fstr(pinfo->cinfo, COL_INFO, " (exec was called from TID %d, which inherited TID %d of the main thread)", old_tid, dissector_data->pid.linux);

    return 0;
}

static int dissect_linux_process_exit_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct traceshark_dissector_data *dissector_data = (struct traceshark_dissector_data *)data;
    proto_item *process_event_item = NULL;
    proto_tree *process_event_tree = NULL;
    fvalue_t *fv;
    gint32 exit_code;

    // get exit code
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.syscalls.sys_enter_exit_group.error_code");
    exit_code = (gint32)fvalue_get_sinteger64(fv);

    // update process tracking with this event
    if (capture_ordered_chronologically && !pinfo->fd->visited)
        dissector_data->process_info.linux = traceshark_update_linux_process_exit_group(dissector_data->machine_id, &pinfo->abs_ts, pinfo->num, dissector_data->pid.linux, exit_code);

    dissect_common_info(tvb, pinfo, tree, &process_event_item, &process_event_tree, dissector_data, PROCESS_EXIT, FALSE);

    traceshark_proto_tree_add_int(process_event_tree, hf_exit_code_linux, tvb, 0, 0, exit_code);
    col_append_fstr(pinfo->cinfo, COL_INFO, " has called exit_group() with exit status %d. All active threads will now be terminated.", exit_code);

    return 0;
}

static int dissect_linux_process_exit(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct traceshark_dissector_data *dissector_data = (struct traceshark_dissector_data *)data;
    proto_item *process_event_item = NULL;
    proto_tree *process_event_tree = NULL;
    fvalue_t *fv;
    const gchar *name;

    // get process name
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.sched.sched_process_exit.comm");
    name = wmem_strbuf_get_str(fvalue_get_strbuf(fv));

    // update process tracking with this event
    if (capture_ordered_chronologically && !pinfo->fd->visited)
        dissector_data->process_info.linux = traceshark_update_linux_process_exit(dissector_data->machine_id, &pinfo->abs_ts, pinfo->num, dissector_data->pid.linux, name);

    dissect_common_info(tvb, pinfo, tree, &process_event_item, &process_event_tree, dissector_data, PROCESS_EXIT, TRUE);

    col_append_fstr(pinfo->cinfo, COL_INFO, " has exited");

    return 0;
}

void proto_register_process(void)
{
    static gint *ett[] = {
        &ett_process,
        &ett_clone_flags
    };

    static hf_register_info hf[] = {
        { &hf_event,
          { "Event Type", "process_event.event",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Process event type", HFILL }
        },
        { &hf_is_thread_event,
          { "Is Thread Event", "process_event.is_thread_event",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_creator_pid_linux,
          { "Creator PID", "process_event.creator_pid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Creator process ID", HFILL }
        },
        { &hf_creator_tid,
          { "Creator TID", "process_event.creator_tid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Creator thread ID", HFILL }
        },
        { &hf_child_pid_linux,
          { "Child PID", "process_event.child_pid",
            FT_INT32, BASE_DEC, NULL, 0,
            "New child process ID", HFILL }
        },
        { &hf_child_tid,
          { "Child TID", "process_event.child_tid",
            FT_INT32, BASE_DEC, NULL, 0,
            "New child thread ID", HFILL }
        },
        { &hf_child_name,
          { "Child Name", "process_event.child_name",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "New child process name", HFILL }
        },
        { &hf_clone_flags,
          { "Clone Flags", "process_event.clone_flags",
            FT_UINT64, BASE_HEX, NULL,
            0x0000000000000000, "Linux clone flags", HFILL }
        },
        { &hf_clone_flags_csignal,
          { "CSIGNAL", "process_event.clone_flags.csignal",
            FT_UINT64, BASE_HEX, NULL,
            0x00000000000000ff, NULL, HFILL }
        },
        { &hf_clone_flags_clone_vm,
          { "CLONE_VM", "process_event.clone_flags.clone_vm",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000000000100, NULL, HFILL }
        },
        { &hf_clone_flags_clone_fs,
          { "CLONE_FS", "process_event.clone_flags.clone_fs",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000000000200, NULL, HFILL }
        },
        { &hf_clone_flags_clone_files,
          { "CLONE_FILES", "process_event.clone_flags.clone_files",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000000000400, NULL, HFILL }
        },
        { &hf_clone_flags_clone_sighand,
          { "CLONE_SIGHAND", "process_event.clone_flags.clone_sighand",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000000000800, NULL, HFILL }
        },
        { &hf_clone_flags_clone_pidfd,
          { "CLONE_PIDFD", "process_event.clone_flags.clone_pidfd",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000000001000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_ptrace,
          { "CLONE_PTRACE", "process_event.clone_flags.clone_ptrace",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000000002000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_vfork,
          { "CLONE_VFORK", "process_event.clone_flags.clone_vfork",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000000004000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_parent,
          { "CLONE_PARENT", "process_event.clone_flags.clone_parent",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000000008000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_thread,
          { "CLONE_THREAD", "process_event.clone_flags.clone_thread",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000000010000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_newns,
          { "CLONE_NEWNS", "process_event.clone_flags.clone_newns",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000000020000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_sysvsem,
          { "CLONE_SYSVSEM", "process_event.clone_flags.clone_sysvsem",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000000040000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_settls,
          { "CLONE_SETTLS", "process_event.clone_flags.clone_settls",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000000080000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_parent_settid,
          { "CLONE_PARENT_SETTID", "process_event.clone_flags.clone_parent_settid",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000000100000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_child_cleartid,
          { "CLONE_CHILD_CLEARTID", "process_event.clone_flags.clone_child_cleartid",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000000200000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_detached,
          { "CLONE_DETACHED", "process_event.clone_flags.clone_detached",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000000400000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_untraced,
          { "CLONE_UNTRACED", "process_event.clone_flags.clone_untraced",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000000800000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_child_settid,
          { "CLONE_CHILD_SETTID", "process_event.clone_flags.clone_child_settid",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000001000000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_newcgroup,
          { "CLONE_NEWCGROUP", "process_event.clone_flags.clone_newcgroup",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000002000000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_newuts,
          { "CLONE_NEWUTS", "process_event.clone_flags.clone_newuts",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000004000000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_newipc,
          { "CLONE_NEWIPC", "process_event.clone_flags.clone_newipc",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000008000000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_newuser,
          { "CLONE_NEWUSER", "process_event.clone_flags.clone_newuser",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000010000000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_newpid,
          { "CLONE_NEWPID", "process_event.clone_flags.clone_newpid",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000020000000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_newnet,
          { "CLONE_NEWNET", "process_event.clone_flags.clone_newnet",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000040000000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_io,
          { "CLONE_IO", "process_event.clone_flags.clone_io",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000080000000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_clear_sighand,
          { "CLONE_CLEAR_SIGHAND", "process_event.clone_flags.clone_clear_sighand",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000100000000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_into_cgroup,
          { "CLONE_INTO_CGROUP", "process_event.clone_flags.clone_into_cgroup",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000200000000, NULL, HFILL }
        },
        { &hf_clone_flags_clone_newtime,
          { "CLONE_NEWTIME", "process_event.clone_flags.clone_newtime",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            0x0000000000000080, NULL, HFILL }
        },
        { &hf_old_tid_linux,
          { "Old TID", "process_event.old_tid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Previous TID (when a thread that isn't the thread group leader executes a file, all other threads are terminated and the executing thread inherits the leader's TID)", HFILL }
        },
        { &hf_exec_file,
          { "Exec File", "process_event.exec_file",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "File being executed", HFILL }
        },
        { &hf_exit_code_linux,
          { "Exit Code", "process_event.exit_code",
            FT_INT32, BASE_DEC, NULL, 0,
            "Process exit code", HFILL }
        }
    };

    proto_process = proto_register_protocol("Process Event", "PROCESS", "process_event");
    proto_register_field_array(proto_process, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    // register subscribed fields
    traceshark_register_field_subscription("linux_trace_event.data.syscalls.sys_enter_exit_group.error_code");
    traceshark_register_field_subscription("linux_trace_event.data.sched.sched_process_exec.filename");
    traceshark_register_field_subscription("linux_trace_event.data.sched.sched_process_exec.old_pid");
    traceshark_register_field_subscription("linux_trace_event.data.task.task_newtask.pid");
    traceshark_register_field_subscription("linux_trace_event.data.task.task_newtask.comm");
    traceshark_register_field_subscription("linux_trace_event.data.task.task_newtask.clone_flags");
    traceshark_register_field_subscription("linux_trace_event.data.sched.sched_process_exit.comm");
}

void proto_reg_handoff_process(void)
{
    static dissector_handle_t linux_process_fork_handle, linux_process_exec_handle, linux_process_exit_group_handle,
                              linux_process_exit_handle;

    linux_process_fork_handle = create_dissector_handle(dissect_linux_process_fork, proto_process);
    linux_process_exec_handle = create_dissector_handle(dissect_linux_process_exec, proto_process);
    linux_process_exit_group_handle = create_dissector_handle(dissect_linux_process_exit_group, proto_process);
    linux_process_exit_handle = create_dissector_handle(dissect_linux_process_exit, proto_process);
    
    // register to relevant trace events
    dissector_add_string("linux_trace_event.system_and_name", "task/task_newtask", linux_process_fork_handle);
    dissector_add_string("linux_trace_event.system_and_name", "sched/sched_process_exec", linux_process_exec_handle);
    dissector_add_string("linux_trace_event.system_and_name", "syscalls/sys_enter_exit_group", linux_process_exit_group_handle);
    dissector_add_string("linux_trace_event.system_and_name", "sched/sched_process_exit", linux_process_exit_handle);
}