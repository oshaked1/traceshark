#include <epan/packet.h>
#include <epan/traceshark.h>
#include <wiretap/traceshark.h>

static int proto_linux_trace_event = -1;

static dissector_table_t event_system_and_name_dissector_table;

static int hf_big_endian = -1;
static int hf_cpu = -1;
static int hf_event_id = -1;
static int hf_event_name = -1;
static int hf_event_system = -1;
static int hf_event_system_and_name = -1;

static gint ett_linux_trace_event = -1;
static gint ett_common_fields = -1;
static gint ett_event_specific_fields = -1;

/**
 * Additional frame fields
*/
static int proto_frame = -1;
static int hf_pid_linux = -1;

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

struct type_display {
    enum ftenum type;
    int display;
    const void *format_cb;
};

static void format_data_loc(gchar *buf, guint32 val)
{
    g_snprintf(buf, ITEM_LABEL_LENGTH, "0x%x (offset = 0x%x, size = 0x%x)", val, val & 0xffff, val >> 16);
}

/**
 * Determine the field type and display based on the field format data.
 */
static void get_field_type_display(const struct linux_trace_event_field *field, struct type_display *info)
{
    info->format_cb = NULL;

    // signed types
    if (strcmp(field->type, "short")            == 0 ||
        strcmp(field->type, "signed short")     == 0 ||
        strcmp(field->type, "int")              == 0 ||
        strcmp(field->type, "signed int")       == 0 ||
        strcmp(field->type, "signed")           == 0 ||
        strcmp(field->type, "long")             == 0 ||
        strcmp(field->type, "signed long")      == 0 ||
        strcmp(field->type, "long long")        == 0 ||
        strcmp(field->type, "signed long long") == 0 ||
        strcmp(field->type, "s16")              == 0 ||
        strcmp(field->type, "s32")              == 0 ||
        strcmp(field->type, "s64")              == 0 ||
        strcmp(field->type, "ssize_t")          == 0 ||
        strcmp(field->type, "pid_t")            == 0) {
        
        switch (field->size) {
            case 2:
                info->type = FT_INT16;
                info->display = BASE_DEC;
                return;
            case 4:
                info->type = FT_INT32;
                info->display = BASE_DEC;
                return;
            case 8:
                info->type = FT_INT64;
                info->display = BASE_DEC;
                return;
        }
    }

    // unsigned types
    if (strcmp(field->type, "unsigned short")       == 0 ||
        strcmp(field->type, "unsigned int")         == 0 ||
        strcmp(field->type, "unsigned")             == 0 ||
        strcmp(field->type, "unsigned long")        == 0 ||
        strcmp(field->type, "unsigned long long")   == 0 ||
        strcmp(field->type, "u16")                  == 0 ||
        strcmp(field->type, "u32")                  == 0 ||
        strcmp(field->type, "u64")                  == 0 ||
        strcmp(field->type, "size_t")               == 0 ||
        strstr(field->type, "enum")                 == field->type) {
        
        switch (field->size) {
            case 2:
                info->type = FT_UINT16;
                info->display = BASE_DEC_HEX;
                return;
            case 4:
                info->type = FT_UINT32;
                info->display = BASE_DEC_HEX;
                return;
            case 8:
                info->type = FT_UINT64;
                info->display = BASE_DEC_HEX;
                return;
        }
    }

    // pointer
    else if (field->type[strlen(field->type) - 1] == '*') {
        switch (field->size) {
            case 4:
                info->type = FT_UINT32;
                info->display = BASE_HEX;
                return;
            case 8:
                info->type = FT_UINT64;
                info->display = BASE_HEX;
                return;
        }
    }

    // bool
    else if (strcmp(field->type, "bool") == 0) {
        info->type = FT_BOOLEAN;
        info->display = BASE_NONE;
        return;
    }

    // string
    else if (strstr(field->type, "char[") == field->type || (strcmp(field->type, "char") == 0 && field->is_array)) {
        info->type = FT_STRING;
        info->display = BASE_NONE;
        return;
    }

    // __data_loc
    else if (strstr(field->type, "__data_loc") == field->type && field->size == 4) {
        info->type = FT_UINT32;
        info->display = BASE_CUSTOM;
        info->format_cb = CF_FUNC(format_data_loc);
        return;
    }

    // default is FT_BYTES and BASE_NONE if we didn't find a better match
    info->type = FT_BYTES;
    info->display = BASE_NONE;
}

static void dynamic_hf_populate_field(hf_register_info *hf, const struct linux_trace_event_field *field, const gchar *event_system, const gchar *event_name)
{
    struct type_display info;

    hf->p_id = wmem_new(wmem_file_scope(), int);
    *(hf->p_id) = -1;

    hf->hfinfo.name = g_strdup(field->full_definition);

    if (strstr(field->name, "common_") == field->name)
        hf->hfinfo.abbrev = g_strdup_printf("linux_trace_event.data.%s", field->name);
    else if (field->is_data_loc)
        hf->hfinfo.abbrev = g_strdup_printf("linux_trace_event.data.%s.%s.%s_data_loc", event_system, event_name, field->name);
    else
        hf->hfinfo.abbrev = g_strdup_printf("linux_trace_event.data.%s.%s.%s", event_system, event_name, field->name);
    
    // get type and display
    get_field_type_display(field, &info);
    
    hf->hfinfo.type = info.type;
    hf->hfinfo.display = info.display;
    hf->hfinfo.strings = info.format_cb;
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

static void dissect_event_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *common_fields_tree, proto_tree *event_specific_fields_tree, const struct linux_trace_event_format *format, const struct dynamic_hf *dynamic_hf, guint encoding)
{
    struct linux_trace_event_field *field;
    int i;
    guint32 offset, size;
    guint32 *data_loc = NULL;

    // go through all fields, keeping track of the index for accessing the dynamic hf array
    for (i = 0, field = format->fields; i < dynamic_hf->len; i++, field = field->next) {
        DISSECTOR_ASSERT(field != NULL);

        // offset and size come from the format unless it's variable data
        offset = field->offset;
        size = field->size;

        // if the field is a variable data field, fetch the data location first
        if (field->is_variable_data) {
            data_loc = wmem_map_lookup(variable_data_loc, field);
            DISSECTOR_ASSERT(data_loc != NULL);

            offset = *data_loc & 0xffff;
            size = *data_loc >> 16;
        }

        // add the field
        if (strstr(field->name, "common_") == field->name)
            traceshark_proto_tree_add_item(common_fields_tree, *(dynamic_hf->hf[i].p_id), tvb, offset, size, encoding);
        else
            traceshark_proto_tree_add_item(event_specific_fields_tree, *(dynamic_hf->hf[i].p_id), tvb, offset, size, encoding);
        
        // if the field is a __data_loc field, populate the corresponding data field's offset and size
        if (field->is_data_loc) {
            DISSECTOR_ASSERT_HINT(field->data_field != NULL, "No reference to data field in data_loc field");

            data_loc = wmem_new(pinfo->pool, guint32);
            *data_loc = tvb_get_guint32(tvb, offset, encoding);

            wmem_map_insert(variable_data_loc, field->data_field, data_loc);
        }
    }
}

static int dissect_linux_trace_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *linux_trace_event_item, *item;
    proto_tree *linux_trace_event_tree, *common_fields_tree, *event_specific_fields_tree, *frame_tree;
    struct event_options *metadata;
    struct linux_trace_event_options *linux_trace_event_metadata;
    guint encoding;
    guint16 event_id;
    const struct linux_trace_event_format *format;
    size_t system_and_name_len;
    gchar *system_and_name;
    struct dynamic_hf *dynamic_hf;
    fvalue_t *pid_val;
    gint32 pid;
    struct traceshark_dissector_data *dissector_data = (struct traceshark_dissector_data *)data;

    metadata = (struct event_options *)ws_buffer_start_ptr(&pinfo->rec->options_buf);
    linux_trace_event_metadata = &metadata->type_specific_options.linux_trace_event;

    encoding = linux_trace_event_metadata->big_endian ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LINUX_TRACE_EVENT");
    col_add_fstr(pinfo->cinfo, COL_INFO, "CPU = %u", linux_trace_event_metadata->cpu);

    // create Linux trace event tree
    linux_trace_event_item = proto_tree_add_item(tree, proto_linux_trace_event, tvb, 0, -1, ENC_NA);
    linux_trace_event_tree = proto_item_add_subtree(linux_trace_event_item, ett_linux_trace_event);

    // populate event metadata fields
    item = traceshark_proto_tree_add_uint(linux_trace_event_tree, hf_big_endian, tvb, 0, 0, (guint8)linux_trace_event_metadata->big_endian);
    proto_item_set_generated(item);
    item = traceshark_proto_tree_add_uint(linux_trace_event_tree, hf_cpu, tvb, 0, 0, linux_trace_event_metadata->cpu);
    proto_item_set_generated(item);

    // dissect event ID and fetch the event format
    item = traceshark_proto_tree_add_item(linux_trace_event_tree, hf_event_id, tvb, 0, 2, encoding);
    event_id = tvb_get_guint16(tvb, 0, encoding);

    format = epan_get_linux_trace_event_format(pinfo->epan, dissector_data->machine_id, event_id);
    DISSECTOR_ASSERT_HINT(format != NULL, "Could not fetch event format");

    item = traceshark_proto_tree_add_string(linux_trace_event_tree, hf_event_system, tvb, 0, 2, format->system);
    proto_item_set_generated(item);

    item = traceshark_proto_tree_add_string(linux_trace_event_tree, hf_event_name, tvb, 0, 2, format->name);
    proto_item_set_generated(item);

    system_and_name_len = strlen(format->system) + 1 + strlen(format->name) + 1;
    system_and_name = wmem_alloc(pinfo->pool, system_and_name_len);
    g_snprintf(system_and_name, (gulong)system_and_name_len, "%s/%s", format->system, format->name);
    item = traceshark_proto_tree_add_string(linux_trace_event_tree, hf_event_system_and_name, tvb, 0, 2, system_and_name);
    proto_item_set_generated(item);

    // add subtrees for common fields and event specific fields
    common_fields_tree = proto_tree_add_subtree(linux_trace_event_tree, tvb, 0, -1, ett_common_fields, NULL, "Common Fields");
    event_specific_fields_tree = proto_tree_add_subtree(linux_trace_event_tree, tvb, 0, -1, ett_event_specific_fields, NULL, "Event Specific Fields");

    // get dynamic field array
    dynamic_hf = get_dynamic_hf(dissector_data->machine_id, event_id, format);

    // dissect event according to format
    dissect_event_data(tvb, pinfo, common_fields_tree, event_specific_fields_tree, format, dynamic_hf, encoding);

    // get PID field
    pid_val = traceshark_subscribed_field_get_single_value_or_null("linux_trace_event.data.common_pid");

    if (pid_val) {
        pid = fvalue_get_sinteger(pid_val);

        // add PID to info column
        col_append_fstr(pinfo->cinfo, COL_INFO, ", PID = %d", pid);

        // add PID field to frame tree
        frame_tree = proto_find_subtree(tree, proto_frame);
        traceshark_proto_tree_add_int(frame_tree, hf_pid_linux, tvb, 0, 0, pid);

        // initialize process info
        dissector_data->process = wmem_new0(pinfo->pool, struct traceshark_process);
        dissector_data->process->pid._linux = pid;
    }

    // add event system and name to info column
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", system_and_name);

    // call dissector for this event
    dissector_try_string(event_system_and_name_dissector_table, system_and_name, tvb, pinfo, tree, dissector_data);

    return tvb_captured_length(tvb);
}

void proto_register_linux_trace_event(void)
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
          "Event name", HFILL }
        },
        { &hf_event_system,
          { "Event System", "linux_trace_event.system",
          FT_STRINGZ, BASE_NONE, NULL, 0,
          "Event system", HFILL }
        },
        { &hf_event_system_and_name,
          { "Event System and Name", "linux_trace_event.system_name",
          FT_STRINGZ, BASE_NONE, NULL, 0,
          "Event system and name", HFILL }
        }
    };
    
    proto_linux_trace_event = proto_register_protocol("Linux Trace Event",
        "LINUX_TRACE_EVENT", "linux_trace_event");
    proto_register_field_array(proto_linux_trace_event, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    static hf_register_info frame_hf[] = {
        { &hf_pid_linux,
          { "PID", "frame.pid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Linux PID (identifies a thread)", HFILL }
        }
    };

    proto_frame = proto_get_id_by_filter_name("frame");
    proto_register_field_array(proto_frame, frame_hf, array_length(frame_hf));

    // create dynamic field array map and register a callback to free the arrays when the map is destroyed
    dynamic_hf_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_int64_hash, g_int64_equal);
    wmem_register_callback(wmem_file_scope(), dynamic_hf_map_destroy_cb, NULL);

    // create variable data field location map
    variable_data_loc = wmem_map_new_autoreset(wmem_epan_scope(), wmem_packet_scope(), g_direct_hash, g_direct_equal);

    // register subscribed fields
    traceshark_register_field_subscription("linux_trace_event.data.common_pid");

    // register event system and name dissector table
    event_system_and_name_dissector_table = register_dissector_table("linux_trace_event.system_name",
        "Linux trace event system and name", proto_linux_trace_event, FT_STRINGZ, FALSE);
}

void proto_reg_handoff_linux_trace_event(void)
{
    static dissector_handle_t linux_trace_event_handle;

    linux_trace_event_handle = create_dissector_handle(dissect_linux_trace_event, proto_linux_trace_event);
    
    // register to event type dissector table
    dissector_add_uint("frame.event_type", EVENT_TYPE_LINUX_TRACE_EVENT, linux_trace_event_handle);
}