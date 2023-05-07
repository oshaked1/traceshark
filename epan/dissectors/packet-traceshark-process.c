#include <epan/packet.h>
#include <epan/traceshark.h>
#include <wiretap/traceshark.h>

#define CLONE_THREAD 0x00010000

static int proto_process = -1;

static int hf_event = -1;
static int hf_event_name = -1;
static int hf_child_pid_linux = -1;
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
static int hf_old_pid_linux = -1;
static int hf_exec_file = -1;
static int hf_error_code = -1;

static gint ett_process = -1;
static gint ett_clone_flags = -1;

const value_string process_events[] = {
    { PROCESS_FORK, "Process Fork" },
    { PROCESS_FORK_THREAD, "Thread Fork" },
    { PROCESS_EXEC, "Process Exec" },
    { PROCESS_EXIT, "Process Exit" },
    { 0, "NULL" }
};

static const true_false_string tfs_generic = { "True", "False" };

static void dissect_common_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree **process_event_item, proto_item **process_event_tree, struct traceshark_dissector_data *dissector_data, enum process_event_type event)
{
    const gchar *event_str;
    proto_item *item;

    *process_event_item = proto_tree_add_item(tree, proto_process, tvb, 0, 0, ENC_NA);
    *process_event_tree = proto_item_add_subtree(*process_event_item, ett_process);

    switch (event) {
        case PROCESS_FORK:
        case PROCESS_EXEC:
        case PROCESS_EXIT:
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "PROCESS");
            break;
        case PROCESS_FORK_THREAD:
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "THREAD");
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }

    event_str = try_val_to_str(event, process_events);
    DISSECTOR_ASSERT(event_str != NULL);
    col_add_str(pinfo->cinfo, COL_INFO, event_str);
    proto_item_append_text(*process_event_item, ": %s", event_str);

    traceshark_proto_tree_add_uint(*process_event_tree, hf_event, tvb, 0, 0, event);
    item = traceshark_proto_tree_add_string(*process_event_tree, hf_event_name, tvb, 0, 0, event_str);
    proto_item_set_hidden(item);

    // add PID according to its type
    switch (dissector_data->event_type) {
        case EVENT_TYPE_LINUX_TRACE_EVENT:
            col_append_fstr(pinfo->cinfo, COL_INFO, ": PID %d", dissector_data->process->pid._linux);
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }

    // add process name
    if (dissector_data->process->name != NULL)
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", dissector_data->process->name);
}

static void dissect_clone_flags(tvbuff_t *tvb, proto_tree *tree, guint64 clone_flags)
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

static int dissect_process_fork(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct traceshark_dissector_data *dissector_data = (struct traceshark_dissector_data *)data;
    proto_item *process_event_item = NULL;
    proto_tree *process_event_tree = NULL;
    fvalue_t *fv;
    union pid child_pid;
    const gchar *child_name;
    guint64 clone_flags;
    gboolean is_thread;

    // get child PID
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.task.task_newtask.pid");
    child_pid._linux = fvalue_get_sinteger(fv);

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
    is_thread = (clone_flags & CLONE_THREAD) == CLONE_THREAD;

    // update PID lifecycle with this event
    if (!pinfo->fd->visited)
        dissector_data->process = traceshark_update_process_fork(dissector_data->machine_id, &pinfo->abs_ts, pinfo->num, dissector_data->process->pid, child_pid, child_name);

    dissect_common_info(tvb, pinfo, tree, &process_event_item, &process_event_tree, dissector_data, is_thread ? PROCESS_FORK_THREAD : PROCESS_FORK);
    traceshark_proto_tree_add_int(process_event_tree, hf_child_pid_linux, tvb, 0, 0, child_pid._linux);
    traceshark_proto_tree_add_string(process_event_tree, hf_child_name, tvb, 0, 0, child_name);
    col_append_fstr(pinfo->cinfo, COL_INFO, " has spawned a new %s with PID %d (%s)", is_thread ? "thread" : "process", child_pid._linux, child_name);
    dissect_clone_flags(tvb, process_event_tree, clone_flags);

    proto_item_append_text(process_event_item, " (%d -> %d)", dissector_data->process->pid._linux, child_pid._linux);

    return 0;
}

static int dissect_process_exec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct traceshark_dissector_data *dissector_data = (struct traceshark_dissector_data *)data;
    proto_item *process_event_item = NULL;
    proto_tree *process_event_tree = NULL;
    fvalue_t *fv;
    const gchar *exec_file;
    union pid old_pid;

    dissect_common_info(tvb, pinfo, tree, &process_event_item, &process_event_tree, dissector_data, PROCESS_EXEC);

    // get exec file
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.sched.sched_process_exec.filename");
    exec_file = wmem_strbuf_get_str(fvalue_get_strbuf(fv));
    traceshark_proto_tree_add_string(process_event_tree, hf_exec_file, tvb, 0, 0, exec_file);

    col_append_fstr(pinfo->cinfo, COL_INFO, " is executing %s", exec_file);
    proto_item_append_text(process_event_item, " (%s)", exec_file);

    // get old PID
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.sched.sched_process_exec.old_pid");
    old_pid._linux = fvalue_get_sinteger(fv);
    traceshark_proto_tree_add_int(process_event_tree, hf_old_pid_linux, tvb, 0, 0, old_pid._linux);

    if (old_pid._linux != dissector_data->process->pid._linux)
        col_append_fstr(pinfo->cinfo, COL_INFO, " (exec was called from thread with PID %d, which inherited PID %d of the main thread)", old_pid._linux, dissector_data->process->pid._linux);

    return 0;
}

static int dissect_process_exit(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct traceshark_dissector_data *dissector_data = (struct traceshark_dissector_data *)data;
    proto_item *process_event_item = NULL;
    proto_tree *process_event_tree = NULL;
    fvalue_t *fv;
    union exit_code error_code;

    // get exit code
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.syscalls.sys_enter_exit_group.error_code");
    error_code._linux = (gint32)fvalue_get_sinteger64(fv);

    // update PID lifecycle with this event
    if (!pinfo->fd->visited)
        dissector_data->process = traceshark_update_process_exit(dissector_data->machine_id, &pinfo->abs_ts, pinfo->num, dissector_data->process->pid, TRUE, error_code);

    dissect_common_info(tvb, pinfo, tree, &process_event_item, &process_event_tree, dissector_data, PROCESS_EXIT);

    traceshark_proto_tree_add_int(process_event_tree, hf_error_code, tvb, 0, 0, error_code._linux);
    col_append_fstr(pinfo->cinfo, COL_INFO, " has called exit_group() with error code %d. All active threads will now be terminated.", error_code._linux);

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
          { "Event", "process_event.event",
            FT_UINT16, BASE_DEC, VALS(process_events), 0,
            "Process event type", HFILL }
        },
        { &hf_event_name,
          { "Event Name", "process_event.event_name",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Process event name", HFILL }
        },
        { &hf_child_pid_linux,
          { "Child PID", "process_event.child_pid",
            FT_INT32, BASE_DEC, NULL, 0,
            "New child process ID", HFILL }
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
        { &hf_old_pid_linux,
          { "Old PID", "process_event.old_pid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Previous PID (when a process that isn't the thread group leader executes a file, all other threads are terminated and the executing thread inherits the leader's PID)", HFILL }
        },
        { &hf_exec_file,
          { "Exec File", "process_event.exec_file",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "File being executed", HFILL }
        },
        { &hf_error_code,
          { "Exit Code", "process_event.error_code",
            FT_INT32, BASE_DEC, NULL, 0,
            "Process exit error code", HFILL }
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
}

void proto_reg_handoff_process(void)
{
    static dissector_handle_t process_fork_handle, process_exec_handle, process_exit_handle;

    process_fork_handle = create_dissector_handle(dissect_process_fork, proto_process);
    process_exec_handle = create_dissector_handle(dissect_process_exec, proto_process);
    process_exit_handle = create_dissector_handle(dissect_process_exit, proto_process);
    
    // register to relevant trace events
    dissector_add_string("linux_trace_event.system_name", "task/task_newtask", process_fork_handle);
    dissector_add_string("linux_trace_event.system_name", "sched/sched_process_exec", process_exec_handle);
    dissector_add_string("linux_trace_event.system_name", "syscalls/sys_enter_exit_group", process_exit_handle);
}