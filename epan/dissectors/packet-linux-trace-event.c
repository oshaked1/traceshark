#include <epan/packet.h>
#include <wiretap/traceshark.h>

static int proto_linux_trace_event = -1;

static int hf_big_endian = -1;
static int hf_cpu = -1;

static gint ett_linux_trace_event = -1;

static const value_string endianness_vals[] = {
    { 0, "Little Endian" },
    { 1, "Big Endian" },
    { 0, "NULL" }
};

static int
dissect_linux_trace_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *linux_trace_event_item, *ti;
    proto_tree *linux_trace_event_tree;
    struct linux_trace_event_options *metadata;

    metadata = &((struct event_options *)ws_buffer_start_ptr(&pinfo->rec->options_buf))->type_specific_options.linux_trace_event;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LINUX_TRACE_EVENT");
    col_add_fstr(pinfo->cinfo, COL_INFO, "CPU = %u", metadata->cpu);

    // create Linux trace event tree
    linux_trace_event_item = proto_tree_add_item(tree, proto_linux_trace_event, tvb, 0, -1, ENC_NA);
    linux_trace_event_tree = proto_item_add_subtree(linux_trace_event_item, ett_linux_trace_event);

    // populate event metadata fields
    ti = proto_tree_add_uint(linux_trace_event_tree, hf_big_endian, tvb, 0, 0, (guint8)metadata->big_endian);
    proto_item_set_generated(ti);
    ti = proto_tree_add_uint(linux_trace_event_tree, hf_cpu, tvb, 0, 0, metadata->cpu);
    proto_item_set_generated(ti);

    return tvb_captured_length(tvb);
}

void
proto_register_linux_trace_event(void)
{
    static gint *ett[] = {
        &ett_linux_trace_event
    };
    
    static hf_register_info hf[] = {
        { &hf_big_endian,
          { "Endianness", "linux_trace_event.endianness",
            FT_UINT8, BASE_DEC, VALS(endianness_vals), 0,
            "Endianness (byte order)", HFILL }
        },
        { &hf_cpu,
          { "CPU", "linux_trace_event.cpu",
          FT_UINT32, BASE_DEC, NULL, 0,
          "CPU number on which the event occurred", HFILL }
        }
    };
    
    proto_linux_trace_event = proto_register_protocol("Linux Trace Event",
        "LINUX_TRACE_EVENT", "linux_trace_event");
    proto_register_field_array(proto_linux_trace_event, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_linux_trace_event(void)
{
    static dissector_handle_t linux_trace_event_handle;

    linux_trace_event_handle = create_dissector_handle(dissect_linux_trace_event, proto_linux_trace_event);
    
    // register to event type dissector table
    dissector_add_uint("frame.event_type", EVENT_TYPE_LINUX_TRACE_EVENT, linux_trace_event_handle);
}