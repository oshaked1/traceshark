#include <epan/packet.h>
#include <epan/traceshark.h>
#include <wiretap/traceshark.h>

static int proto_trace_event = -1;

static dissector_table_t event_type_dissector_table;

/**
 * Frame fields
*/
static int proto_frame = -1;
static int hf_machine_id = -1;
static int hf_event_type = -1;

static int
dissect_trace_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree *frame_tree;
    struct event_options *metadata;
    
    DISSECTOR_ASSERT(pinfo->rec->rec_type == REC_TYPE_FT_SPECIFIC_EVENT);
    metadata = (struct event_options *)ws_buffer_start_ptr(&pinfo->rec->options_buf);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TRACE_EVENT");
    col_add_fstr(pinfo->cinfo, COL_INFO, "Machine ID = %u, Event Type = %u", metadata->machine_id, metadata->event_type);

    // add fields to frame tree
    frame_tree = proto_find_subtree(tree, proto_frame);
    // initial dissection pass doesn't create the frame tree, so we shouldn't assert its existence
    if (frame_tree) {
        proto_tree_add_uint(frame_tree, hf_machine_id, tvb, 0, 0, metadata->machine_id);
        proto_tree_add_uint(frame_tree, hf_event_type, tvb, 0, 0, metadata->event_type);
    }

    // call dissector for this event type
    return dissector_try_uint(event_type_dissector_table, metadata->event_type, tvb, pinfo, tree);
}

void
proto_register_trace_event(void)
{
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

    event_type_dissector_table = register_dissector_table("frame.event_type", "Trace Event Type", proto_trace_event, FT_UINT16, BASE_DEC);
}

void
proto_reg_handoff_trace_event(void)
{
    dissector_handle_t trace_event_handle;

    trace_event_handle = create_dissector_handle(dissect_trace_event, proto_trace_event);
    
    // register to wtap_fts_rec dissector table for all supported trace file types
    dissector_add_uint("wtap_fts_rec", tracecmd_get_file_type_subtype(), trace_event_handle);

    // register to pcapng block type dissector table
    dissector_add_uint("pcapng.block_type", BLOCK_TYPE_EVENT, trace_event_handle);
}