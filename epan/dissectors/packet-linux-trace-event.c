#include <epan/packet.h>
#include <epan/traceshark.h>
#include <wiretap/traceshark.h>

/**
 * Frame fields
*/
static int proto_frame = -1;
static int hf_machine_id = -1;
static int hf_event_type = -1;

/**
 * Event Metadata fields
*/
static int proto_event_metadata = -1;
static int hf_big_endian = -1;
static int hf_cpu = -1;

/**
 * Linux trace event fields
*/
static int proto_linux_trace_event = -1;

/**
 * Subtrees
*/
static gint ett_event_metadata = -1;

static const value_string endianness_vals[] = {
    { 0, "Little Endian" },
    { 1, "Big Endian" },
    { 0, "NULL" }
};

static int
dissect_linux_trace_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *event_metadata_item;
    proto_tree *frame_tree, *event_metadata_tree;
    struct event_options *metadata = (struct event_options *)ws_buffer_start_ptr(&pinfo->rec->options_buf);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LINUX_TRACE_EVENT");
    col_clear(pinfo->cinfo, COL_INFO);

    // add fields to frame tree
    frame_tree = find_subtree(tree, proto_frame);
    // initial dissection pass doesn't create the frame tree, so we shouldn't assert its existence
    if (frame_tree) {
        proto_tree_add_uint(frame_tree, hf_machine_id, tvb, 0, 0, metadata->machine_id);
        proto_tree_add_uint(frame_tree, hf_event_type, tvb, 0, 0, metadata->event_type);
    }

    // create event metadata tree
    struct linux_trace_event_options *linux_trace_event_metadata = &metadata->type_specific_options.linux_trace_event;
    event_metadata_item = proto_tree_add_item(tree, proto_event_metadata, tvb, 0, 0, ENC_NA);
    event_metadata_tree = proto_item_add_subtree(event_metadata_item, ett_event_metadata);
    proto_tree_add_uint(event_metadata_tree, hf_big_endian, tvb, 0, 0, (guint8)linux_trace_event_metadata->big_endian);
    proto_tree_add_uint(event_metadata_tree, hf_cpu, tvb, 0, 0, linux_trace_event_metadata->cpu);

    // create Linux trace event tree
    proto_tree_add_item(tree, proto_linux_trace_event, tvb, 0, -1, ENC_NA);

    return tvb_captured_length(tvb);
}

void
proto_register_linux_trace_event(void)
{
    static gint *ett[] = {
        &ett_event_metadata
    };

    proto_register_subtree_array(ett, array_length(ett));

    static hf_register_info frame_hf[] = {
        { &hf_machine_id,
          { "Machine ID", "frame.machine_id",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Machine ID as present in the trace file", HFILL }
        },
        { &hf_event_type,
          { "Event Type", "frame.event_type",
            FT_UINT16, BASE_DEC, VALS(traceshark_event_types), 0,
            "The type of trace event", HFILL }
        }
    };

    proto_frame = proto_get_id_by_filter_name("frame");
    proto_register_field_array(proto_frame, frame_hf, array_length(frame_hf));

    proto_linux_trace_event = proto_register_protocol("Linux Trace Event",
        "LINUX_TRACE_EVENT", "linux_trace_event");
    
    static hf_register_info event_metadata_hf[] = {
        { &hf_big_endian,
          { "Endianness", "event.endianness",
            FT_UINT8, BASE_DEC, VALS(endianness_vals), 0,
            "Endianness (byte order)", HFILL }
        },
        { &hf_cpu,
          { "CPU", "event.cpu",
          FT_UINT32, BASE_DEC, NULL, 0,
          "CPU number on which the event occurred", HFILL }
        }
    };
    
    proto_event_metadata = proto_register_protocol("Event Metadata", "EVENT", "event");
    proto_register_field_array(proto_event_metadata, event_metadata_hf, array_length(event_metadata_hf));
}

void
proto_reg_handoff_linux_trace_event(void)
{
    static dissector_handle_t linux_trace_event_handle;

    linux_trace_event_handle = create_dissector_handle(dissect_linux_trace_event, proto_linux_trace_event);
    dissector_add_uint("wtap_fts_rec", tracecmd_get_file_type_subtype(), linux_trace_event_handle);
}