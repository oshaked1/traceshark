#include <epan/packet.h>

#include <wiretap/trace-cmd.h>

static int proto_linux_trace_event = -1;

static int
dissect_linux_trace_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LINUX_TRACE_EVENT");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_tree_add_item(tree, proto_linux_trace_event, tvb, 0, -1, ENC_NA);

    return tvb_captured_length(tvb);
}

void
proto_register_linux_trace_event(void)
{
    proto_linux_trace_event = proto_register_protocol("Linux Trace Event",
            "LINUX_TRACE_EVENT", "linux_trace_event");
}

void
proto_reg_handoff_linux_trace_event(void)
{
    static dissector_handle_t linux_trace_event_handle;

    linux_trace_event_handle = create_dissector_handle(dissect_linux_trace_event, proto_linux_trace_event);
    dissector_add_uint("wtap_fts_rec", tracecmd_get_file_type_subtype(), linux_trace_event_handle);
}