#include <epan/packet.h>
#include <epan/traceshark.h>

static int proto_ptrace = -1;

static int hf_request = -1;
static int hf_pid = -1;
static int hf_addr = -1;
static int hf_data = -1;
static int hf_options = -1;
static int hf_ptrace_option_tracesysgood = -1;
static int hf_ptrace_option_tracefork = -1;
static int hf_ptrace_option_tracevfork = -1;
static int hf_ptrace_option_traceclone = -1;
static int hf_ptrace_option_traceexec = -1;
static int hf_ptrace_option_tracevforkdone = -1;
static int hf_ptrace_option_traceexit = -1;
static int hf_ptrace_option_traceseccomp = -1;
static int hf_ptrace_option_exitkill = -1;
static int hf_ptrace_option_suspend_seccomp = -1;
static int hf_regset = -1;

static gint ett_ptrace = -1;
static gint ett_ptrace_options = -1;

enum ptrace_requests {
    PTRACE_TRACEME      = 0,
    PTRACE_CONT         = 7,
    PTRACE_ATTACH       = 16,
    PTRACE_SYSCALL      = 24,
    PTRACE_GETEVENTMSG  = 0x4201,
    PTRACE_GETSIGINFO   = 0x4202,
    PTRACE_GETREGSET    = 0x4204,
    PTRACE_SEIZE        = 0x4206,
    PTRACE_INTERRUPT    = 0x4207,
    PTRACE_LISTEN       = 0x4208
};

static const val64_string ptrace_request_strs[] = {
    { PTRACE_TRACEME,       "PTRACE_TRACEME" },
    { PTRACE_CONT,          "PTRACE_CONT" },
    { PTRACE_ATTACH,        "PTRACE_ATTACH" },
    { PTRACE_SYSCALL,       "PTRACE_SYSCALL" },
    { PTRACE_GETEVENTMSG,   "PTRACE_GETEVENTMSG" },
    { PTRACE_GETSIGINFO,    "PTRACE_GETSIGINFO" },
    { PTRACE_GETREGSET,     "PTRACE_GETREGSET" },
    { PTRACE_SEIZE,         "PTRACE_SEIZE" },
    { PTRACE_INTERRUPT,     "PTRACE_INTERRUPT" },
    { PTRACE_LISTEN,        "PTRACE_LISTEN" },
    { 0, "NULL" }
};

#define PTRACE_O_TRACESYSGOOD       1
#define PTRACE_O_TRACEFORK          (1 << 1)
#define PTRACE_O_TRACEVFORK         (1 << 2)
#define PTRACE_O_TRACECLONE         (1 << 3)
#define PTRACE_O_TRACEEXEC          (1 << 4)
#define PTRACE_O_TRACEVFORKDONE     (1 << 5)
#define PTRACE_O_TRACEEXIT          (1 << 6)
#define PTRACE_O_TRACESECCOMP       (1 << 7)
#define PTRACE_O_EXITKILL           (1 << 20)
#define PTRACE_O_SUSPEND_SECCOMP    (1 << 21)

enum ptrace_regsets {
    NT_PRSTATUS = 1
};

static const val64_string ptrace_regset_strs[] = {
    { NT_PRSTATUS,  "NT_PRSTATUS" },
    { 0, "NULL" }
};

static const true_false_string tfs_generic = { "True", "False" };

static const gchar *get_options_str(packet_info *pinfo, guint64 options)
{
    wmem_strbuf_t *strbuf = wmem_strbuf_new(pinfo->pool, "");
    const gchar *str;

    if (options & PTRACE_O_TRACESYSGOOD)
        wmem_strbuf_append(strbuf, ", PTRACE_O_TRACESYSGOOD");
    if (options & PTRACE_O_TRACEFORK)
        wmem_strbuf_append(strbuf, ", PTRACE_O_TRACEFORK");
    if (options & PTRACE_O_TRACEVFORK)
        wmem_strbuf_append(strbuf, ", PTRACE_O_TRACEVFORK");
    if (options & PTRACE_O_TRACECLONE)
        wmem_strbuf_append(strbuf, ", PTRACE_O_TRACECLONE");
    if (options & PTRACE_O_TRACEEXEC)
        wmem_strbuf_append(strbuf, ", PTRACE_O_TRACEEXEC");
    if (options & PTRACE_O_TRACEVFORKDONE)
        wmem_strbuf_append(strbuf, ", PTRACE_O_TRACEVFORKDONE");
    if (options & PTRACE_O_TRACEEXIT)
        wmem_strbuf_append(strbuf, ", PTRACE_O_TRACEEXIT");
    if (options & PTRACE_O_TRACESECCOMP)
        wmem_strbuf_append(strbuf, ", PTRACE_O_TRACESECCOMP");
    if (options & PTRACE_O_EXITKILL)
        wmem_strbuf_append(strbuf, ", PTRACE_O_EXITKILL");
    if (options & PTRACE_O_SUSPEND_SECCOMP)
        wmem_strbuf_append(strbuf, ", PTRACE_O_SUSPEND_SECCOMP");
    
    str = wmem_strbuf_get_str(strbuf);

    // if there were options, discard the comma and space at the beginning of the string
    if (strlen(str) > 0)
        return &str[2];
    else
        return str;
}

static void dissect_options(tvbuff_t *tvb, proto_tree *tree, guint64 options)
{
    static int * const options_fields[] = {
		&hf_ptrace_option_tracesysgood,
        &hf_ptrace_option_tracefork,
        &hf_ptrace_option_tracevfork,
        &hf_ptrace_option_traceclone,
        &hf_ptrace_option_traceexec,
        &hf_ptrace_option_tracevforkdone,
        &hf_ptrace_option_traceexit,
        &hf_ptrace_option_traceseccomp,
        &hf_ptrace_option_exitkill,
        &hf_ptrace_option_suspend_seccomp,
		NULL
	};

	proto_tree_add_bitmask_value(tree, tvb, 0, hf_options, ett_ptrace_options, options_fields, options);
}

static void dissect_request_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, enum ptrace_requests request, const gchar *request_str,
                               pid_t pid, guint64 addr, guint64 data, struct traceshark_dissector_data *dissector_data)
{
    const gchar *options_str, *regset_str, *target_process_name, *pid_str;
    const struct linux_process_info *target_process;

    target_process = traceshark_get_linux_process_by_pid(dissector_data->machine_id, pid, &pinfo->abs_ts);
    target_process_name = traceshark_linux_process_get_name(target_process, &pinfo->abs_ts);

    if (target_process_name != NULL)
        pid_str = wmem_strdup_printf(pinfo->pool, "%d (%s)", pid, target_process_name);
    else
        pid_str = wmem_strdup_printf(pinfo->pool, "%d", pid);

    switch (request) {
        case PTRACE_SYSCALL:
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s request: resume PID %s with ", request_str, pid_str);

            // signal was given to tracee
            if (data != 0)
                col_append_fstr(pinfo->cinfo, COL_INFO, "signal %d ", (gint32)data);
            else
                col_append_str(pinfo->cinfo, COL_INFO, "no signal ");
            
            col_append_str(pinfo->cinfo, COL_INFO, "until next syscall entry/exit");
            break;
        
        case PTRACE_GETEVENTMSG:
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s request: copy the message associated with the last event of PID %s to address 0x%llx",
                         request_str, pid_str, data);
            break;
        
        case PTRACE_GETSIGINFO:
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s request: copy last signal info from PID %s to address 0x%llx", request_str, pid_str, data);
            break;
        
        case PTRACE_GETREGSET:
            traceshark_proto_tree_add_uint64(tree, hf_regset, tvb, 0, 0, addr);
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s request: copy ", request_str);
            regset_str = try_val64_to_str(addr, ptrace_regset_strs);

            // known regset
            if (regset_str != NULL)
                col_append_fstr(pinfo->cinfo, COL_INFO, "register set %s ", regset_str);
            else
                col_append_str(pinfo->cinfo, COL_INFO, "unknown register set ");
            
            col_append_fstr(pinfo->cinfo, COL_INFO, "of PID %s to address 0x%llx", pid_str, data);
            break;
        
        case PTRACE_SEIZE:
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s request: seize PID %s with ", request_str, pid_str);
            options_str = get_options_str(pinfo, data);

            // no options
            if (strlen(options_str) == 0)
                col_append_str(pinfo->cinfo, COL_INFO, "no options");
            else
                col_append_fstr(pinfo->cinfo, COL_INFO, "options %s", options_str);
            
            dissect_options(tvb, tree, data);
            break;
        
        case PTRACE_INTERRUPT:
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s request: interrupt PID %s", request_str, pid_str);
            break;
        
        case PTRACE_LISTEN:
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s request: restart PID %s", request_str, pid_str);
            break;
    }
}

static int dissect_ptrace_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct traceshark_dissector_data *dissector_data = (struct traceshark_dissector_data *)data;
    proto_item *ptrace_item;
    proto_tree *ptrace_tree;
    fvalue_t *fv;
    guint64 request, addr, ptrace_data;
    const gchar *request_str;
    pid_t pid;

    ptrace_item = proto_tree_add_item(tree, proto_ptrace, tvb, 0, 0, ENC_NA);
    ptrace_tree = proto_item_add_subtree(ptrace_item, ett_ptrace);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PTRACE");

    // add ptrace request
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.syscalls.sys_enter_ptrace.request");
    request = (guint64)fvalue_get_sinteger64(fv);
    traceshark_proto_tree_add_uint64(ptrace_tree, hf_request, tvb, 0, 0, request);

    // add PID
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.syscalls.sys_enter_ptrace.pid");
    pid = (pid_t)fvalue_get_sinteger64(fv);
    traceshark_proto_tree_add_int(ptrace_tree, hf_pid, tvb, 0, 0, pid);

    // add address
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.syscalls.sys_enter_ptrace.addr");
    addr = fvalue_get_uinteger64(fv);
    traceshark_proto_tree_add_uint64(ptrace_tree, hf_addr, tvb, 0, 0, addr);

    // add data
    fv = traceshark_subscribed_field_get_single_value("linux_trace_event.data.syscalls.sys_enter_ptrace.data");
    ptrace_data = fvalue_get_uinteger64(fv);
    traceshark_proto_tree_add_uint64(ptrace_tree, hf_data, tvb, 0, 0, ptrace_data);

    // set info with raw parameters
    request_str = try_val64_to_str(request, ptrace_request_strs);
    if (request_str != NULL)
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s request: ", request_str);
    else
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown request 0x%llx: ", request);
    col_append_fstr(pinfo->cinfo, COL_INFO, "PID = %d, address = 0x%llx, data = 0x%llx", pid, addr, ptrace_data);

    // perform dissection according to event type
    dissect_request_info(tvb, pinfo, ptrace_tree, request, request_str, pid, addr, ptrace_data, dissector_data);
    
    return 0;
}

void proto_register_ptrace(void)
{
    static gint *ett[] = {
        &ett_ptrace,
        &ett_ptrace_options
    };

    static hf_register_info hf[] = {
        { &hf_request,
          { "Request", "ptrace.request",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS64(ptrace_request_strs), 0,
            "Ptrace request", HFILL }
        },
        { &hf_pid,
          { "PID", "ptrace.pid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Target PID", HFILL }
        },
        { &hf_addr,
          { "Address", "ptrace.addr",
            FT_UINT64, BASE_HEX, NULL, 0,
            "Memory address", HFILL }
        },
        { &hf_data,
          { "Data", "ptrace.data",
            FT_UINT64, BASE_HEX, NULL, 0,
            "Data", HFILL }
        },
        { &hf_options,
          { "Options", "ptrace.options",
            FT_UINT64, BASE_HEX, NULL,
            0, "Ptrace options", HFILL }
        },
        { &hf_ptrace_option_tracesysgood,
          { "PTRACE_O_TRACESYSGOOD", "ptrace.options.tracesysgood",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            PTRACE_O_TRACESYSGOOD, NULL, HFILL }
        },
        { &hf_ptrace_option_tracefork,
          { "PTRACE_O_TRACEFORK", "ptrace.options.tracefork",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            PTRACE_O_TRACEFORK, NULL, HFILL }
        },
        { &hf_ptrace_option_tracevfork,
          { "PTRACE_O_TRACEVFORK", "ptrace.options.tracevfork",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            PTRACE_O_TRACEVFORK, NULL, HFILL }
        },
        { &hf_ptrace_option_traceclone,
          { "PTRACE_O_TRACECLONE", "ptrace.options.traceclone",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            PTRACE_O_TRACECLONE, NULL, HFILL }
        },
        { &hf_ptrace_option_traceexec,
          { "PTRACE_O_TRACEEXEC", "ptrace.options.traceexec",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            PTRACE_O_TRACEEXEC, NULL, HFILL }
        },
        { &hf_ptrace_option_tracevforkdone,
          { "PTRACE_O_TRACEVFORKDONE", "ptrace.options.tracevforkdone",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            PTRACE_O_TRACEVFORKDONE, NULL, HFILL }
        },
        { &hf_ptrace_option_traceexit,
          { "PTRACE_O_TRACEEXIT", "ptrace.options.traceexit",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            PTRACE_O_TRACEEXIT, NULL, HFILL }
        },
        { &hf_ptrace_option_traceseccomp,
          { "PTRACE_O_TRACESECCOMP", "ptrace.options.traceseccomp",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            PTRACE_O_TRACESECCOMP, NULL, HFILL }
        },
        { &hf_ptrace_option_exitkill,
          { "PTRACE_O_EXITKILL", "ptrace.options.exitkill",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            PTRACE_O_EXITKILL, NULL, HFILL }
        },
        { &hf_ptrace_option_suspend_seccomp,
          { "PTRACE_O_SUSPEND_SECCOMP", "ptrace.options.suspend_seccomp",
            FT_BOOLEAN, 64, TFS(&tfs_generic),
            PTRACE_O_SUSPEND_SECCOMP, NULL, HFILL }
        },
        { &hf_regset,
          { "Register Set", "ptrace.regset",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS64(ptrace_regset_strs),
            0, "Ptrace register set", HFILL }
        },
    };

    proto_ptrace = proto_register_protocol("Ptrace Request", "PTRACE", "ptrace");
    proto_register_field_array(proto_ptrace, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    // register subscribed fields
    traceshark_register_field_subscription("linux_trace_event.data.syscalls.sys_enter_ptrace.request");
    traceshark_register_field_subscription("linux_trace_event.data.syscalls.sys_enter_ptrace.pid");
    traceshark_register_field_subscription("linux_trace_event.data.syscalls.sys_enter_ptrace.addr");
    traceshark_register_field_subscription("linux_trace_event.data.syscalls.sys_enter_ptrace.data");
}

void proto_reg_handoff_ptrace(void)
{
    static dissector_handle_t ptrace_request_handle;

    ptrace_request_handle = create_dissector_handle(dissect_ptrace_request, proto_ptrace);

    // register to relevant trace events
    dissector_add_string("linux_trace_event.system_and_name", "syscalls/sys_enter_ptrace", ptrace_request_handle);
}