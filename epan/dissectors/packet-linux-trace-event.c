#include <epan/packet.h>
#include <wiretap/traceshark.h>

static int proto_linux_trace_event = -1;

static int hf_big_endian = -1;
static int hf_cpu = -1;
static int hf_event_id = -1;
static int hf_event_name = -1;
static int hf_event_system = -1;

static gint ett_linux_trace_event = -1;
static gint ett_common_fields = -1;
static gint ett_event_specific_fields = -1;

static const value_string endianness_vals[] = {
    { 0, "Little Endian" },
    { 1, "Big Endian" },
    { 0, "NULL" }
};

struct dynamic_hf {
    int len;
    hf_register_info *hf;
};

#define DYNAMIC_HF_KEY(machine_id, event_id) (((guint64)(machine_id) << 32) + (event_id))

/**
 * This map contains registered dynamic field arrays based on a key which is a
 * combination of a mahcine ID and event ID.
 * The idea is that each event has a number of fields which will be stored in
 * a single dynamic field array.
 * Additionally, a single file may contain events from more than one machine,
 * with conflicting field definitions (different event name to ID mappings and
 * even different field types and definitions for the same event).
 */
static wmem_map_t *dynamic_hf_map;

/**
 * This map contains the offset and size of a variable data field.
 * The key is a pointer to its field info (struct linux_trace_event_field),
 * and the data is a guint32 which is the corresponding __data_loc field's value.
 */
static wmem_map_t *variable_data_loc;

static void free_dynamic_hf(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
    int i;
    struct hf_register_info *field;
    struct dynamic_hf *dynamic_hf = value;

    for (i = 0; i < dynamic_hf->len; i++) {
        field = &dynamic_hf->hf[i];
        proto_deregister_field(proto_linux_trace_event, *(field->p_id));
    }
    proto_add_deregistered_data(dynamic_hf->hf);
}

static gboolean dynamic_hf_map_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data _U_)
{
    wmem_map_foreach(dynamic_hf_map, free_dynamic_hf, NULL);

    // return TRUE so this callback isn't unregistered
    return TRUE;
}

/**
 * Determine the field type based on the field format data.
 * This is not implemented yet, so all fields are determined to be raw bytes.
 */
static enum ftenum field_type(const struct linux_trace_event_field *field _U_)
{
    // default is FT_BYTES if we don't find a better match
    enum ftenum type = FT_BYTES;

    return type;
}

static int field_display(enum ftenum type)
{
    switch (type) {
        case FT_BYTES:
            return BASE_NONE;
        default:
            return BASE_NONE;
    }
}

static void dynamic_hf_populate_field(hf_register_info *hf, const struct linux_trace_event_field *field, const gchar *event_system, const gchar *event_name)
{
    hf->p_id = wmem_new(wmem_file_scope(), int);
    *(hf->p_id) = -1;

    if (strncmp(field->name, "common_", 7) == 0) {
        hf->hfinfo.name = g_strdup(field->name);
        hf->hfinfo.abbrev = g_strdup_printf("linux_trace_event_data.%s", field->name);
    }
    else if (field->is_data_loc) {
        hf->hfinfo.name = g_strdup_printf("%s (data_loc)", field->name);
        hf->hfinfo.abbrev = g_strdup_printf("linux_trace_event_data.%s.%s.%s_data_loc", event_system, event_name, field->name);
    }
    else {
        hf->hfinfo.name = g_strdup(field->name);
        hf->hfinfo.abbrev = g_strdup_printf("linux_trace_event_data.%s.%s.%s", event_system, event_name, field->name);
    }
    
    hf->hfinfo.type = field_type(field);
    hf->hfinfo.display = field_display(hf->hfinfo.type);
    hf->hfinfo.strings = NULL;
    hf->hfinfo.bitmask = 0;
    hf->hfinfo.blurb = g_strdup(field->name);
    HFILL_INIT(hf[0]);
}

static struct dynamic_hf *get_dynamic_hf(guint32 machine_id, guint16 event_id, const struct linux_trace_event_format *format)
{
    struct linux_trace_event_field *field;
    guint64 key;
    guint64 *pkey;
    int i;
    struct dynamic_hf *dynamic_hf = NULL;

    // check if the dynamic field array map has an entry for this machine id and event id
    key = DYNAMIC_HF_KEY(machine_id, event_id);
    dynamic_hf = wmem_map_lookup(dynamic_hf_map, &key);

    // entry found - return it
    if (dynamic_hf != NULL)
        return dynamic_hf;

    // entry not found - generate dynamic hf, register it and populate the map
    dynamic_hf = wmem_new(wmem_file_scope(), struct dynamic_hf);

    // walk the field list to find how many are there
    dynamic_hf->len = 0;
    field = format->fields;
    while (field != NULL) {
        dynamic_hf->len++;
        field = field->next;
    }

    // allocate dynamic field array
    dynamic_hf->hf = g_new0(hf_register_info, dynamic_hf->len);

    // walk the field list again, this time populating the dynamic field array
    i = 0;
    field = format->fields;
    while (field != NULL) {
        dynamic_hf_populate_field(&dynamic_hf->hf[i], field, format->system, format->name);
        field = field->next;
        i++;
    }

    // register the dynamic field array
    proto_register_field_array(proto_linux_trace_event, dynamic_hf->hf, dynamic_hf->len);

    // add it to the map and return it
    pkey = wmem_new(wmem_file_scope(), guint64); // this is necessary because the pointer itself must stay valid
    *pkey = key;
    wmem_map_insert(dynamic_hf_map, pkey, dynamic_hf);
    return dynamic_hf;
}

static void
dissect_event_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *common_fields_tree, proto_tree *event_specific_fields_tree, const struct linux_trace_event_format *format, const struct dynamic_hf *dynamic_hf, guint encoding)
{
    struct linux_trace_event_field *field;
    int i;
    guint32 *data_loc = NULL;

    // go through all fields, keeping track of the index for accessing the dynamic hf array
    for (i = 0, field = format->fields; i < dynamic_hf->len; i++, field = field->next) {
        DISSECTOR_ASSERT(field != NULL);

        // if the field is a variable data field, fetch the data location first
        if (field->is_variable_data) {
            data_loc = wmem_map_lookup(variable_data_loc, field);
            DISSECTOR_ASSERT(data_loc != NULL);

            field->offset = *data_loc & 0xffff;
            field->size = *data_loc >> 16;
        }

        // add the field
        if (strncmp(field->name, "common_", 7) == 0)
            proto_tree_add_item(common_fields_tree, *(dynamic_hf->hf[i].p_id), tvb, field->offset, field->size, encoding);
        else
            proto_tree_add_item(event_specific_fields_tree, *(dynamic_hf->hf[i].p_id), tvb, field->offset, field->size, encoding);

        // if the field is a __data_loc field, populate the corresponding data field's offset and size
        if (field->is_data_loc) {
            DISSECTOR_ASSERT(field->data_field != NULL);

            data_loc = wmem_new(pinfo->pool, guint32);
            *data_loc = tvb_get_guint32(tvb, field->offset, encoding);

            wmem_map_insert(variable_data_loc, field->data_field, data_loc);
        }
    }
}

static int
dissect_linux_trace_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *linux_trace_event_item, *item;
    proto_tree *linux_trace_event_tree, *common_fields_tree, *event_specific_fields_tree;
    struct event_options *metadata;
    struct linux_trace_event_options *linux_trace_event_metadata;
    guint encoding;
    guint16 event_id;
    const struct linux_trace_event_format *format;
    struct dynamic_hf *dynamic_hf;

    metadata = (struct event_options *)ws_buffer_start_ptr(&pinfo->rec->options_buf);
    linux_trace_event_metadata = &metadata->type_specific_options.linux_trace_event;

    encoding = linux_trace_event_metadata->big_endian ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LINUX_TRACE_EVENT");
    col_add_fstr(pinfo->cinfo, COL_INFO, "CPU = %u", linux_trace_event_metadata->cpu);

    // create Linux trace event tree
    linux_trace_event_item = proto_tree_add_item(tree, proto_linux_trace_event, tvb, 0, -1, ENC_NA);
    linux_trace_event_tree = proto_item_add_subtree(linux_trace_event_item, ett_linux_trace_event);

    // populate event metadata fields
    item = proto_tree_add_uint(linux_trace_event_tree, hf_big_endian, tvb, 0, 0, (guint8)linux_trace_event_metadata->big_endian);
    proto_item_set_generated(item);
    item = proto_tree_add_uint(linux_trace_event_tree, hf_cpu, tvb, 0, 0, linux_trace_event_metadata->cpu);
    proto_item_set_generated(item);

    // dissect event ID and fetch the event format
    item = proto_tree_add_item(linux_trace_event_tree, hf_event_id, tvb, 0, 2, encoding);
    event_id = tvb_get_guint16(tvb, 0, encoding);
    format = epan_get_linux_trace_event_format(pinfo->epan, metadata->machine_id, event_id);
    DISSECTOR_ASSERT(format != NULL);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s/%s", format->system, format->name);
    item = proto_tree_add_string(linux_trace_event_tree, hf_event_system, tvb, 0, 2, format->system);
    proto_item_set_generated(item);
    item = proto_tree_add_string(linux_trace_event_tree, hf_event_name, tvb, 0, 2, format->name);
    proto_item_set_generated(item);

    // add subtrees for common fields and event specific fields
    common_fields_tree = proto_tree_add_subtree(linux_trace_event_tree, tvb, 0, -1, ett_common_fields, NULL, "Common Fields");
    event_specific_fields_tree = proto_tree_add_subtree(linux_trace_event_tree, tvb, 0, -1, ett_event_specific_fields, NULL, "Event Specific Fields");

    // get dynamic field array
    dynamic_hf = get_dynamic_hf(metadata->machine_id, event_id, format);

    // dissect event according to format
    dissect_event_data(tvb, pinfo, common_fields_tree, event_specific_fields_tree, format, dynamic_hf, encoding);

    return tvb_captured_length(tvb);
}

void
proto_register_linux_trace_event(void)
{
    static gint *ett[] = {
        &ett_linux_trace_event,
        &ett_common_fields,
        &ett_event_specific_fields
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
        },
        { &hf_event_id,
          { "Event ID", "linux_trace_event.id",
          FT_UINT16, BASE_DEC, NULL, 0,
          "Event ID", HFILL }
        },
        { &hf_event_name,
          { "Event Name", "linux_trace_event.name",
          FT_STRINGZ, BASE_NONE, NULL, 0,
          "Event Name", HFILL }
        },
        { &hf_event_system,
          { "Event System", "linux_trace_event.system",
          FT_STRINGZ, BASE_NONE, NULL, 0,
          "Event System", HFILL }
        }
    };
    
    proto_linux_trace_event = proto_register_protocol("Linux Trace Event",
        "LINUX_TRACE_EVENT", "linux_trace_event");
    proto_register_field_array(proto_linux_trace_event, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    // create dynamic field array map and register a callback to free the arrays when the map is destroyed
    dynamic_hf_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_int64_hash, g_int64_equal);
    wmem_register_callback(wmem_file_scope(), dynamic_hf_map_destroy_cb, NULL);

    // create variable data field location map
    variable_data_loc = wmem_map_new_autoreset(wmem_epan_scope(), wmem_packet_scope(), g_direct_hash, g_direct_equal);
}

void
proto_reg_handoff_linux_trace_event(void)
{
    static dissector_handle_t linux_trace_event_handle;

    linux_trace_event_handle = create_dissector_handle(dissect_linux_trace_event, proto_linux_trace_event);
    
    // register to event type dissector table
    dissector_add_uint("frame.event_type", EVENT_TYPE_LINUX_TRACE_EVENT, linux_trace_event_handle);
}