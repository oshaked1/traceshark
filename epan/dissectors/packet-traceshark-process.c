#include <epan/packet.h>
#include <epan/traceshark.h>
#include <wiretap/traceshark.h>

static int proto_process = -1;

static int hf_event = -1;
static int hf_pid_linux = -1;
static int hf_error_code = -1;
static int hf_exec_file = -1;
static int hf_old_pid_linux = -1;
static int hf_child_pid_linux = -1;
static int hf_child_name = -1;

static gint ett_process = -1;

enum process_events {
    PROCESS_FORK,
    PROCESS_EXEC,
    PROCESS_EXIT
};

const value_string process_events[] = {
    { PROCESS_FORK, "Fork" },
    { PROCESS_EXEC, "Exec" },
    { PROCESS_EXIT, "Exit" },
    { 0, "NULL" }
};

static proto_tree *dissect_common_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct traceshark_dissector_data *dissector_data, enum process_event event)
{
    proto_item *process_item;
    proto_tree *process_tree;
    const gchar *event_str;

    process_item = proto_tree_add_item(tree, proto_process, tvb, 0, 0, ENC_NA);
    process_tree = proto_item_add_subtree(process_item, ett_process);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PROCESS");

    event_str = try_val_to_str(event, process_events);
    DISSECTOR_ASSERT(event_str != NULL);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Process %s", event_str);

    traceshark_proto_tree_add_uint(process_tree, hf_event, tvb, 0, 0, event);

    switch (dissector_data->event_type) {
        case EVENT_TYPE_LINUX_TRACE_EVENT:
            traceshark_proto_tree_add_int(process_tree, hf_pid_linux, tvb, 0, 0, dissector_data->process->pid.linux);
            col_append_fstr(pinfo->cinfo, COL_INFO, ": PID %d", dissector_data->process->pid.linux);
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }

    return process_tree;
}

static int dissect_process_fork(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct traceshark_dissector_data *dissector_data = (struct traceshark_dissector_data *)data;
    proto_tree *process_tree;
    fvalue_t *fv;
    union pid child_pid;
    const gchar *child_name;

    process_tree = dissect_common_info(tvb, pinfo, tree, dissector_data, PROCESS_FORK);

    // get child PID
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.task.task_newtask.pid");
    child_pid.linux = fvalue_get_sinteger(fv);
    traceshark_proto_tree_add_int(process_tree, hf_child_pid_linux, tvb, 0, 0, child_pid.linux);

    // get child name
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.task.task_newtask.comm");
    child_name = wmem_strbuf_get_str(fvalue_get_strbuf(fv));
    traceshark_proto_tree_add_string(process_tree, hf_child_name, tvb, 0, 0, child_name);

    col_append_fstr(pinfo->cinfo, COL_INFO, " has spawned a new child with PID %d (%s)", child_pid.linux, child_name);

    return 0;
}

static int dissect_process_exec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct traceshark_dissector_data *dissector_data = (struct traceshark_dissector_data *)data;
    proto_tree *process_tree;
    fvalue_t *fv;
    const gchar *exec_file;
    union pid old_pid;

    process_tree = dissect_common_info(tvb, pinfo, tree, dissector_data, PROCESS_EXEC);

    // get exec file
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.sched.sched_process_exec.filename");
    exec_file = wmem_strbuf_get_str(fvalue_get_strbuf(fv));
    traceshark_proto_tree_add_string(process_tree, hf_exec_file, tvb, 0, 0, exec_file);

    col_append_fstr(pinfo->cinfo, COL_INFO, " is executing %s", exec_file);

    // get old PID
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.sched.sched_process_exec.old_pid");
    old_pid.linux = fvalue_get_sinteger(fv);
    traceshark_proto_tree_add_int(process_tree, hf_old_pid_linux, tvb, 0, 0, old_pid.linux);

    if (old_pid.linux != dissector_data->process->pid.linux)
        col_append_fstr(pinfo->cinfo, COL_INFO, " (exec was called from thread with PID %d, which inherited PID %d of the main thread)", old_pid.linux, dissector_data->process->pid.linux);

    return 0;
}

static int dissect_process_exit(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct traceshark_dissector_data *dissector_data = (struct traceshark_dissector_data *)data;
    proto_tree *process_tree;
    fvalue_t *fv;
    gint32 error_code;

    process_tree = dissect_common_info(tvb, pinfo, tree, dissector_data, PROCESS_EXIT);

    // get exit code
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.syscalls.sys_enter_exit_group.error_code");
    error_code = (gint32)fvalue_get_sinteger64(fv);
    traceshark_proto_tree_add_int(process_tree, hf_error_code, tvb, 0, 0, error_code);
    col_append_fstr(pinfo->cinfo, COL_INFO, " has called exit_group() with error code %d. All active threads will now be terminated.", error_code);

    return 0;
}

void proto_register_process(void)
{
    static gint *ett[] = {
        &ett_process
    };

    static hf_register_info hf[] = {
        { &hf_event,
          { "Event", "process.event",
            FT_UINT16, BASE_DEC, VALS(process_events), 0,
            "Process event type", HFILL }
        },
        { &hf_pid_linux,
          { "PID", "process.pid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Linux process ID (identifies a thread)", HFILL }
        },
        { &hf_error_code,
          { "Exit Code", "process.error_code",
            FT_INT32, BASE_DEC, NULL, 0,
            "Process exit error code", HFILL }
        },
        { &hf_exec_file,
          { "Exec File", "process.exec_file",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "File being executed", HFILL }
        },
        { &hf_old_pid_linux,
          { "Old PID", "process.old_pid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Previous PID (when a process that isn't the thread group leader executes a file, all other threads are terminated and the executing thread inherits the leader's PID)", HFILL }
        },
        { &hf_child_pid_linux,
          { "Child PID", "process.child_pid",
            FT_INT32, BASE_DEC, NULL, 0,
            "New child process ID", HFILL }
        },
        { &hf_child_name,
          { "Child Name", "process.child_name",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "New child process name", HFILL }
        }
    };

    proto_process = proto_register_protocol("Process", "PROCESS", "process");
    proto_register_field_array(proto_process, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    // register subscribed fields
    traceshark_register_field_subscription("linux_trace_event.data.syscalls.sys_enter_exit_group.error_code");
    traceshark_register_field_subscription("linux_trace_event.data.sched.sched_process_exec.filename");
    traceshark_register_field_subscription("linux_trace_event.data.sched.sched_process_exec.old_pid");
    traceshark_register_field_subscription("linux_trace_event.data.task.task_newtask.pid");
    traceshark_register_field_subscription("linux_trace_event.data.task.task_newtask.comm");
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