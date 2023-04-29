#include <epan/packet.h>
#include <epan/traceshark.h>
#include <wiretap/traceshark.h>

static int proto_process = -1;

static int hf_event = -1;
static int hf_error_code = -1;
static int hf_exec_file = -1;
static int hf_old_pid_linux = -1;
static int hf_child_pid_linux = -1;
static int hf_child_name = -1;

static gint ett_process = -1;

const value_string process_events[] = {
    { PROCESS_FORK, "Fork" },
    { PROCESS_EXEC, "Exec" },
    { PROCESS_EXIT, "Exit" },
    { 0, "NULL" }
};

static void dissect_common_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree **process_event_item, proto_item **process_event_tree, struct traceshark_dissector_data *dissector_data, enum process_event_type event)
{
    const gchar *event_str;

    *process_event_item = proto_tree_add_item(tree, proto_process, tvb, 0, 0, ENC_NA);
    *process_event_tree = proto_item_add_subtree(*process_event_item, ett_process);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PROCESS");

    event_str = try_val_to_str(event, process_events);
    DISSECTOR_ASSERT(event_str != NULL);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Process %s", event_str);
    proto_item_append_text(*process_event_item, ": %s", event_str);

    traceshark_proto_tree_add_uint(*process_event_tree, hf_event, tvb, 0, 0, event);

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

static int dissect_process_fork(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct traceshark_dissector_data *dissector_data = (struct traceshark_dissector_data *)data;
    proto_item *process_event_item = NULL;
    proto_tree *process_event_tree = NULL;
    fvalue_t *fv;
    union pid child_pid;
    const gchar *child_name;

    // get child PID
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.task.task_newtask.pid");
    child_pid._linux = fvalue_get_sinteger(fv);

    // get child name
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.task.task_newtask.comm");
    child_name = wmem_strbuf_get_str(fvalue_get_strbuf(fv));

    // update PID lifecycle with this event
    if (!pinfo->fd->visited)
        dissector_data->process = traceshark_update_process_fork(dissector_data->machine_id, &pinfo->abs_ts, pinfo->num, dissector_data->process->pid, child_pid, child_name);

    dissect_common_info(tvb, pinfo, tree, &process_event_item, &process_event_tree, dissector_data, PROCESS_FORK);
    traceshark_proto_tree_add_int(process_event_tree, hf_child_pid_linux, tvb, 0, 0, child_pid._linux);
    traceshark_proto_tree_add_string(process_event_tree, hf_child_name, tvb, 0, 0, child_name);
    col_append_fstr(pinfo->cinfo, COL_INFO, " has spawned a new child with PID %d (%s)", child_pid._linux, child_name);

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
        &ett_process
    };

    static hf_register_info hf[] = {
        { &hf_event,
          { "Event", "process_event.event",
            FT_UINT16, BASE_DEC, VALS(process_events), 0,
            "Process event type", HFILL }
        },
        { &hf_error_code,
          { "Exit Code", "process_event.error_code",
            FT_INT32, BASE_DEC, NULL, 0,
            "Process exit error code", HFILL }
        },
        { &hf_exec_file,
          { "Exec File", "process_event.exec_file",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "File being executed", HFILL }
        },
        { &hf_old_pid_linux,
          { "Old PID", "process_event.old_pid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Previous PID (when a process that isn't the thread group leader executes a file, all other threads are terminated and the executing thread inherits the leader's PID)", HFILL }
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