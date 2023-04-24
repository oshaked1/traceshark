#include <epan/packet.h>
#include <epan/traceshark.h>
#include <wiretap/traceshark.h>

static int proto_trace_event = -1;

static dissector_table_t event_type_dissector_table;

static int proto_frame = -1;

static int hf_event_type = -1;
static int hf_machine_id = -1;
static int hf_hostname = -1;
static int hf_machine_id_and_hostname = -1;
static int hf_os_type = -1;
static int hf_os_version = -1;
static int hf_arch = -1;
static int hf_num_cpus = -1;

static gint ett_machine_info = -1;

const value_string event_types[] = {
    { EVENT_TYPE_UNKNOWN, "Unknown" },
    { EVENT_TYPE_LINUX_TRACE_EVENT, "Linux Trace Event" },
    { 0, "NULL" }
};

const value_string os_types[] = {
    { OS_UNKNOWN, "Unknown" },
    { OS_LINUX, "Linux" },
    { OS_WINDOWS, "Windows" },
    { 0, "NULL" }
};

const value_string architectures[] = {
    { ARCH_UNKNOWN, "Unknown" },
    { ARCH_X86_32, "x86-32" },
    { ARCH_X86_64, "x86-64" },
    { 0, "NULL" }
};

static int dissect_trace_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *machine_info_item, *item;
    proto_tree *frame_tree, *machine_info_tree;
    struct event_options *metadata;
    struct traceshark_dissector_data *dissector_data;
    const struct traceshark_machine_info_data *machine_info;
    dissector_handle_t event_type_dissector;
    
    DISSECTOR_ASSERT_HINT(pinfo->rec->rec_type == REC_TYPE_FT_SPECIFIC_EVENT, "Exptected REC_TYPE_FT_SPECIFIC_EVENT record");
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

    // fetch machine info and add fields (machine_id == 0 means no machine identity)
    if (metadata->machine_id != 0) {
        machine_info = epan_get_machine_info(pinfo->epan, metadata->machine_id);
        DISSECTOR_ASSERT_HINT(machine_info != NULL, "Couldn't fetch machine info");

        if (machine_info->hostname != NULL) {
            traceshark_proto_tree_add_string(machine_info_tree, hf_hostname, tvb, 0, 0, machine_info->hostname);
            item = traceshark_proto_tree_add_string(machine_info_tree, hf_machine_id_and_hostname, tvb, 0, 0, wmem_strdup_printf(pinfo->pool, "%s (%u)", machine_info->hostname, machine_info->machine_id));
        }
        else
            item = traceshark_proto_tree_add_string(machine_info_tree, hf_machine_id_and_hostname, tvb, 0, 0, wmem_strdup_printf(pinfo->pool, "%u", machine_info->machine_id));
        
        proto_item_set_hidden(item);
        
        traceshark_proto_tree_add_uint(machine_info_tree, hf_os_type, tvb, 0, 0, machine_info->os_type);

        if (machine_info->os_version != NULL)
            traceshark_proto_tree_add_string(machine_info_tree, hf_os_version, tvb, 0, 0, machine_info->os_version);
        
        traceshark_proto_tree_add_uint(machine_info_tree, hf_arch, tvb, 0, 0, machine_info->arch);

        if (machine_info->num_cpus > 0)
            traceshark_proto_tree_add_uint(machine_info_tree, hf_num_cpus, tvb, 0, 0, machine_info->num_cpus);
    }

    // get dissector for this event type
    if ((event_type_dissector = dissector_get_uint_handle(event_type_dissector_table, metadata->event_type)) == NULL)
        return 0;
    
    // initialize dissector data to be passed to next dissector
    dissector_data = wmem_new0(pinfo->pool, struct traceshark_dissector_data);
    dissector_data->machine_id = metadata->machine_id;
    dissector_data->event_type = metadata->event_type;
    
    return call_dissector_only(event_type_dissector, tvb, pinfo, tree, dissector_data);
}

void proto_register_trace_event(void)
{
    static gint *ett[] = {
        &ett_machine_info
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

    proto_frame = proto_get_id_by_filter_name("frame");
    proto_register_field_array(proto_frame, frame_hf, array_length(frame_hf));
    proto_register_subtree_array(ett, array_length(ett));

    event_type_dissector_table = register_dissector_table("frame.event_type", "Trace Event Type", proto_trace_event, FT_UINT16, BASE_DEC);
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