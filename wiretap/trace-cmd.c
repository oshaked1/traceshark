#include "trace-cmd.h"

#include "traceshark.h"
#include "wtap-int.h"
#include "file_wrappers.h"

#define MAX_EVENT G_MAXUINT16

static const unsigned char tracecmd_magic[3] = { 0x17, 0x08, 0x44 };

static const guint32 machine_id = 0; // trace-cmd files contain events from a single system

static int tracecmd_file_type_subtype = -1;

int tracecmd_get_file_type_subtype(void)
{
    return tracecmd_file_type_subtype;
}

struct cpu_data {
    guint64 offset;
    guint64 size;
};

struct rb_iter_state {
    guint32 current_cpu;
    guint64 current_page;
    guint64 current_ts;
};

struct tracecmd {
    gboolean big_endian;
    int long_size;
    guint32 page_size;
    struct linux_trace_event_format *event_formats[MAX_EVENT + 1];
    guint32 num_cpus;
    struct cpu_data *cpu_data;
    struct rb_iter_state state;

    /*
     * Event timestamps are not stored directly in the event,
     * they have to be computed by walking all of the events
     * from the beginning of the ring buffer page and summing time deltas.
     * This is a problem for reading events in a random access fashion,
     * so to solve this problem, we maintain a map of event offset to
     * info that will be populated during the initial reading of the events.
     * Later when an event is to be read from a given offset,
     * we can consult this map to retrieve the timestamp.
     */
    GHashTable *events;
};

/**
 * Read a null-terminated string from a file.
 * The string is allocated by this function,
 * and the caller is responsible for freeing it.
 * Any read failure, including not finding a null-terminator
 * after reading the specified max number of bytes,
 * will result in a NULL being returned.
 * Specifying a max_read of 0 means no limit.
*/
static gchar *file_gets_null_terminated(FILE_T file, gsize max_read)
{
    // no read limit
    if (max_read == 0)
        max_read = (gsize)-1;

    // start with a 16-byte allocation
    gsize current_size = 16;
    gchar *buf = g_malloc(current_size);

    int tmp;
    gsize offset = 0;

    while (offset < max_read)
    {
        // extend the buffer
        if (offset >= current_size) {
            // make sure we're not overflowing (if we are, something's seriously wrong)
            if (current_size >= (gsize)(1 << 31)) { /* check overflow against 32-bit size_t, for extra caution */
                g_free(buf);
                return NULL;
            }
            current_size *= 2;
            buf = g_realloc(buf, current_size);
        }

        tmp = file_getc(file);

        if (tmp == -1) {
            g_free(buf);
            return NULL;
        }

        buf[offset++] = (char)tmp;

        if (tmp == 0)
            break;
    }

    // no null-terminator found
    if (offset == max_read && buf[offset - 1] != 0) {
        g_free(buf);
        return NULL;
    }

    return buf;
}

static gboolean tracecmd_parse_initial(FILE_T fh, struct tracecmd *tracecmd, int *err, gchar **err_info)
{
    char buf[7]; // enough to hold "tracing" without a null-terminator
    gchar *version = NULL;
    int tmp;

    // seek to after the first 3 bytes (file magic)
    if (file_seek(fh, 3, SEEK_SET, err) == -1)
        return FALSE;
    
    // next 7 bytes should be "tracing"
    if (!wtap_read_bytes(fh, &buf, 7, err, err_info))
        return FALSE;
    if (memcmp(&buf, "tracing", 7))
        goto bad_file;
    
    // following is a version string
    version = file_gets_null_terminated(fh, 0);
    if (!version)
        goto read_error;
    // make sure version is 6 (version 7 is not supported)
    if (strcmp(version, "6")) {
        *err_info = g_strdup("unsupported version of trace.dat - only version 6 is supported");
        g_free(version);
        goto unsupported;
    }
    g_free(version);

    // the following byte indicates the file endianness
    tmp = file_getc(fh);
    switch (tmp) {
        case -1:
            goto read_error;
        case 0:
            tracecmd->big_endian = FALSE;
            ws_debug("file is little-endian");
            break;
        case 1:
            tracecmd->big_endian = TRUE;
            ws_debug("file is big-endian");
            break;
        default:
            goto bad_file;
    }

    // next comes the user-space long size
    tracecmd->long_size = file_getc(fh);
    switch (tracecmd->long_size) {
        case -1:
            goto read_error;
        case 4:
        case 8:
            break;
        default:
            goto bad_file;
    }
    ws_debug("long size is %d", tracecmd->long_size);

    // next 4 bytes are the page size
    if (!wtap_read_bytes(fh, &buf, sizeof(guint32), err, err_info))
        return FALSE;
    tracecmd->page_size = tracecmd->big_endian ? pntoh32(buf) : pletoh32(buf);
    ws_debug("page size is %u", tracecmd->page_size);

    return TRUE;

bad_file:
    *err = WTAP_ERR_BAD_FILE;
    return FALSE;

read_error:
    *err = WTAP_ERR_SHORT_READ;
    return FALSE;

unsupported:
    *err = WTAP_ERR_UNSUPPORTED;
    return FALSE;
}

static gboolean tracecmd_parse_header_info(FILE_T fh, struct tracecmd *tracecmd, int *err, gchar **err_info)
{
    char buf[sizeof(guint64)];
    gchar *tmp_str = NULL;
    guint64 header_page_len, header_event_len;

    // the next 12 bytes should be "header_page\0"
    tmp_str = file_gets_null_terminated(fh, 12);
    if (!tmp_str)
        goto read_error;
    if (strcmp(tmp_str, "header_page")) {
        g_free(tmp_str);
        goto bad_file;
    }
    g_free(tmp_str);
    
    // the next 8 bytes are the size of the page header information
    if (!wtap_read_bytes(fh, &buf, sizeof(guint64), err, err_info))
        return FALSE;
    header_page_len = tracecmd->big_endian ? pntoh64(buf) : pletoh64(buf);
    
    // Following is the page header information,
    // taken from /sys/kernel/debug/tracing/events/header_page.
    // We currently have no use for it so we discard it.
    // TODO: make sure there were no changes made to the format.
    if (!wtap_read_bytes(fh, NULL, (unsigned int)header_page_len, err, err_info))
        return FALSE;
    
    // the next 13 bytes should be "header_event\0"
    tmp_str = file_gets_null_terminated(fh, 13);
    if (!tmp_str)
        goto read_error;
    if (strcmp(tmp_str, "header_event")) {
        g_free(tmp_str);
        goto bad_file;
    }
    g_free(tmp_str);
    
    // the next 8 bytes are the size of the event header information
    if (!wtap_read_bytes(fh, &buf, sizeof(guint64), err, err_info))
        return FALSE;
    header_event_len = tracecmd->big_endian ? pntoh64(buf) : pletoh64(buf);

    // Following is the event header information,
    // taken from /sys/kernel/debug/tracing/events/header_event.
    // We currently have no use for it so we discard it.
    // TODO: make sure there were no changes made to the format.
    if (!wtap_read_bytes(fh, NULL, (unsigned int)header_event_len, err, err_info))
        return FALSE;
    
    return TRUE;

bad_file:
    *err = WTAP_ERR_BAD_FILE;
    return FALSE;

read_error:
    *err = WTAP_ERR_SHORT_READ;
    return FALSE;
}

void tracecmd_free_event_format(struct linux_trace_event_format *format)
{
    struct linux_trace_event_field *curr, *next;

    if (!format)
        return;
    
    if (format->name)
        g_free(format->name);
    
    if (format->print_fmt)
        g_free(format->print_fmt);
    
    if (!format->fields)
        return;
    
    curr = format->fields;
    while (curr) {
        g_free(curr->type);
        g_free(curr->name);
        if (curr->length_expression)
            g_free(curr->length_expression);
        next = curr->next;
        g_free(curr);
        curr = next;
    }
}

/**
 * An event format looks like this:
 * 
 * ====================================================================================================
 * name: sched_wakeup
 * ID: 320
 * format:
 *  	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
 *  	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
 *  	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
 *  	field:int common_pid;	offset:4;	size:4;	signed:1;
 *
 *  	field:char comm[16];	offset:8;	size:16;	signed:1;
 *  	field:pid_t pid;	offset:24;	size:4;	signed:1;
 *  	field:int prio;	offset:28;	size:4;	signed:1;
 *  	field:int target_cpu;	offset:32;	size:4;	signed:1;
 *
 * print fmt: "comm=%s pid=%d prio=%d target_cpu=%03d", REC->comm, REC->pid, REC->prio, REC->target_cpu
 * ====================================================================================================
 * 
 * To parse this, we divide it into lines. We check each line for a keyword
 * to determine what it contains, and parse it accordingly.
*/
static gboolean tracecmd_parse_event_format(const gchar *system, const gchar *format_str, struct tracecmd *tracecmd)
{
    gboolean res = FALSE;
    const int max_lines = 100; /* sensible limit */
    gchar **lines = g_strsplit(format_str, "\n", max_lines);
    gchar **parts;
    gchar *tmp_str = NULL;
    guint64 tmp_int;
    gchar *tmp_length_expr;

    struct linux_trace_event_format *format = g_new0(struct linux_trace_event_format, 1);
    format->system = g_strdup(system);
    struct linux_trace_event_field *field = NULL, *data_fields = NULL, *tmp_field, *tmp_data_field;

    const char field_regex[] = "field\\:((.+)\\s((\\w+)(\\[(.*)\\]){0,1}));\\s+offset\\:(\\d+);\\s+size\\:(\\d+);\\s+signed\\:(\\d+);";
    GRegex *regex = g_regex_new((const gchar *)&field_regex, 0, 0, NULL);
    if (!regex)
        goto cleanup;
    GMatchInfo *match_info = NULL;

    for (int i = 0; i < max_lines; i++) {
        // array null-terminator
        if (lines[i] == NULL)
            break;
        
        // first line should be the event name
        if (i == 0) {
            if (!g_strstr_len(lines[i], -1, "name:"))
                goto cleanup;
            parts = g_strsplit(lines[i], " ", 2);
            format->name = g_strdup(parts[1]);
            g_strfreev(parts);
        }

        // second line should be the event ID
        else if (i == 1) {
            if (!g_strstr_len(lines[i], -1, "ID:"))
                goto cleanup;
            parts = g_strsplit(lines[i], " ", 2);
            tmp_str = g_strdup(parts[1]);
            g_strfreev(parts);
            if (!g_ascii_string_to_unsigned(tmp_str, 10, 0, MAX_EVENT, &tmp_int, NULL))
                goto cleanup;
            format->id = (guint16)tmp_int;
            ws_noisy("parsing event ID %u (%s/%s)", format->id, format->system, format->name);
            g_free(tmp_str);
            tmp_str = NULL;

            // now that we know the ID we can place the event into the list
            tracecmd->event_formats[format->id] = format;
        }

        // third line should be "format:"
        else if (i == 2) {
            if (!g_strstr_len(lines[i], -1, "format:"))
                goto cleanup;
        }

        else {
            // last line is print format
            if (g_strstr_len(lines[i], -1, "print fmt:")) {
                format->print_fmt = g_strdup((const gchar *)lines[i] + strlen("print fmt: "));
                break;
            }

            // field line
            if (g_strstr_len(lines[i], -1, "field:")) {
                field = g_new0(struct linux_trace_event_field, 1);
                if (g_regex_match(regex, lines[i], 0, &match_info)) {
                    field->full_definition = g_match_info_fetch(match_info, 1);
                    field->type = g_match_info_fetch(match_info, 2);
                    field->is_data_loc = strstr(field->type, "__data_loc") == field->type;

                    field->name = g_match_info_fetch(match_info, 4);

                    tmp_str = g_match_info_fetch(match_info, 5);
                    field->is_array = strlen(tmp_str) > 0;
                    g_free(tmp_str);
                    tmp_str = NULL;

                    tmp_str = g_match_info_fetch(match_info, 6);
                    // length is not always present
                    if (strlen(tmp_str) > 0) {
                        if (g_ascii_string_to_unsigned(tmp_str, 10, 0, G_MAXUINT32, &tmp_int, NULL))
                            field->length = (guint32)tmp_int;
                        // length may have an expression instead of a number
                        else
                            field->length_expression = g_strdup(tmp_str);
                    }
                    g_free(tmp_str);
                    tmp_str = NULL;

                    tmp_str = g_match_info_fetch(match_info, 7);
                    if (!g_ascii_string_to_unsigned(tmp_str, 10, 0, G_MAXUINT32, &tmp_int, NULL))
                        goto cleanup;
                    field->offset = (guint32)tmp_int;
                    g_free(tmp_str);
                    tmp_str = NULL;

                    tmp_str = g_match_info_fetch(match_info, 8);
                    if (!g_ascii_string_to_unsigned(tmp_str, 10, 0, G_MAXUINT32, &tmp_int, NULL))
                        goto cleanup;
                    field->size = (guint32)tmp_int;
                    g_free(tmp_str);
                    tmp_str = NULL;

                    tmp_str = g_match_info_fetch(match_info, 9);
                    if (!g_ascii_string_to_unsigned(tmp_str, 10, 0, G_MAXUINT32, &tmp_int, NULL))
                        goto cleanup;
                    field->is_signed = (guint32)tmp_int;
                    g_free(tmp_str);
                    tmp_str = NULL;

                    tmp_length_expr = field->length_expression == NULL? "(null)" : field->length_expression;
                    ws_noisy("type=%s is_array=%u name=%s length=%u length_expr=%s offset=%u size=%u signed=%u", field->type, field->is_array, field->name, field->length, tmp_length_expr, field->offset, field->size, field->is_signed);

                    g_match_info_free(match_info);
                    match_info = NULL;

                    // link field into list of fields
                    if (format->fields == NULL)
                        format->fields = field;
                    else {
                        tmp_field = format->fields;
                        while (tmp_field->next != NULL)
                            tmp_field = tmp_field->next;
                        tmp_field->next = field;
                    }

                    /**
                     * Field is __data_loc - duplicate it, change the appropriate fields and add it to the data fields.
                     * __data_loc means this field points to variable sized data in the event.
                     * The type indicated by the field's format is the type of the data, and type of this field
                     * is always a 32-bit integer, where the lower 16 bits indicate the offset and the higher 16-bits
                     * indicate the size of the data.
                     */
                    if (field->is_data_loc) {
                        tmp_data_field = g_new(struct linux_trace_event_field, 1);

                        tmp_data_field->next = NULL;

                        // skip "__data_loc" portion of the field full definition and type
                        tmp_data_field->full_definition = g_strdup(&field->full_definition[11]);
                        tmp_data_field->type = g_strdup(&field->type[11]);

                        tmp_data_field->is_array = field->is_array;
                        tmp_data_field->name = g_strdup(field->name);
                        tmp_data_field->length = field->length;
                        tmp_data_field->length_expression = g_strdup(field->length_expression);
                        tmp_data_field->offset = 0;
                        tmp_data_field->size = 0;
                        tmp_data_field->is_signed = field->is_signed;
                        tmp_data_field->is_data_loc = FALSE;
                        tmp_data_field->is_variable_data = TRUE;
                        tmp_data_field->data_field = NULL;

                        // link the data field to its __data_loc field
                        field->data_field = tmp_data_field;

                        // link the data field into the list of data fields
                        if (data_fields == NULL)
                            data_fields = tmp_data_field;
                        else {
                            tmp_field = data_fields;
                            while (tmp_field->next != NULL)
                                tmp_field = tmp_field->next;
                            tmp_field->next = tmp_data_field;
                        }
                    }
                }
                else
                    goto cleanup;
            }
        }
    }

    // link data fields to end of regular fields list
    if (data_fields != NULL) {
        tmp_field = format->fields;
        while (tmp_field->next != NULL)
            tmp_field = tmp_field->next;
        tmp_field->next = data_fields;
    }

    // make sure print format was encountered
    if (!format->print_fmt)
        goto cleanup;

    res = TRUE;

cleanup:
    g_free(tmp_str);
    g_strfreev(lines);

    if (regex)
        g_regex_unref(regex);
    
    if (match_info)
        g_match_info_free(match_info);
    
    if (format && res == FALSE) {
        tracecmd->event_formats[format->id] = NULL;
        tracecmd_free_event_format(format);
    }

    return res;
}

static gboolean tracecmd_parse_ftrace_events(FILE_T fh, struct tracecmd *tracecmd, int *err, gchar **err_info)
{
    char buf[sizeof(guint64)];
    guint32 num_events;
    guint64 event_format_len;
    gchar *event_format = NULL;

    // next 4 bytes hold the number of ftrace event formats stored in the file
    if (!wtap_read_bytes(fh, &buf, sizeof(guint32), err, err_info))
        return FALSE;
    num_events = tracecmd->big_endian ? pntoh32(buf) : pletoh32(buf);

    ws_debug("parsing %u ftrace events", num_events);

    // execute for each event format in the file
    while (num_events-- > 0) {
        // next 8 bytes are the size of the following event format
        if (!wtap_read_bytes(fh, &buf, sizeof(guint64), err, err_info))
            return FALSE;
        event_format_len = tracecmd->big_endian ? pntoh64(buf) : pletoh64(buf);

        // following is the event format
        event_format = (gchar *)g_malloc(event_format_len + 1);
        if (!wtap_read_bytes(fh, event_format, (unsigned int)event_format_len, err, err_info)) {
            g_free(event_format);
            return FALSE;
        }
        // add a null-terminator
        event_format[event_format_len] = 0;

        // parse the format
        if (!tracecmd_parse_event_format("ftrace", event_format, tracecmd)) {
            g_free(event_format);
            *err = WTAP_ERR_BAD_FILE;
            return FALSE;
        }
        g_free(event_format);
    }

    return TRUE;
}

static gboolean tracecmd_parse_events(FILE_T fh, struct tracecmd *tracecmd, int *err, gchar **err_info)
{
    char buf[sizeof(guint64)];
    guint32 num_systems, num_events;
    guint64 event_format_len;
    gchar *system_name = NULL, *event_format = NULL;

    // next 4 bytes hold the number of event systems stored in the file
    if (!wtap_read_bytes(fh, &buf, sizeof(guint32), err, err_info))
        return FALSE;
    num_systems = tracecmd->big_endian ? pntoh32(buf) : pletoh32(buf);

    ws_debug("parsing %u event systems", num_systems);

    // execute for each event system in the file
    while (num_systems-- > 0) {
        // next comes the (null-terminated) name of the system
        system_name = file_gets_null_terminated(fh, 0);
        if (!system_name) {
            *err = WTAP_ERR_SHORT_READ;
            goto error_cleanup;
        }
        
        // next 4 bytes hold the number of events in this system
        if (!wtap_read_bytes(fh, &buf, sizeof(guint32), err, err_info))
            goto error_cleanup;
        num_events = tracecmd->big_endian ? pntoh32(buf) : pletoh32(buf);

        ws_debug("parsing %u %s events", num_events, system_name);

        // execute for each event in the system
        while (num_events-- > 0) {
            // next 8 bytes are the size of the following event format
            if (!wtap_read_bytes(fh, &buf, sizeof(guint64), err, err_info))
                goto error_cleanup;
            event_format_len = tracecmd->big_endian ? pntoh64(buf) : pletoh64(buf);

            // following is the event format
            event_format = (gchar *)g_malloc(event_format_len + 1);
            if (!wtap_read_bytes(fh, event_format, (unsigned int)event_format_len, err, err_info))
                goto error_cleanup;
            // add a null-terminator
            event_format[event_format_len] = 0;

            // parse the format
            if (!tracecmd_parse_event_format(system_name, event_format, tracecmd)) {
                *err = WTAP_ERR_BAD_FILE;
                goto error_cleanup;
            }
            g_free(event_format);
            event_format = NULL;
        }

        g_free(system_name);
        system_name = NULL;
    }

    return TRUE;

error_cleanup:
    g_free(system_name);
    g_free(event_format);
    return FALSE;
}

static gboolean tracecmd_parse_kallsyms(FILE_T fh, struct tracecmd *tracecmd, int *err, gchar **err_info)
{
    char buf[sizeof(guint32)];
    guint32 kallsyms_len;

    // next 4 bytes hold the length of the kallsysms info (taken from /proc/kallsyms)
    if (!wtap_read_bytes(fh, &buf, sizeof(guint32), err, err_info))
        return FALSE;
    kallsyms_len = tracecmd->big_endian ? pntoh32(buf) : pletoh32(buf);

    // Following is the kallsyms info.
    // We currently don't parse it, so we discard it.
    if (!wtap_read_bytes(fh, NULL, kallsyms_len, err, err_info))
        return FALSE;
    
    return TRUE;
}

static gboolean tracecmd_parse_printk_formats(FILE_T fh, struct tracecmd *tracecmd, int *err, gchar **err_info)
{
    char buf[sizeof(guint32)];
    guint32 printk_formats_len;

    // next 4 bytes hold the length of the printk formats (taken from /sys/kernel/debug/tracing/printk_formats)
    if (!wtap_read_bytes(fh, &buf, sizeof(guint32), err, err_info))
        return FALSE;
    printk_formats_len = tracecmd->big_endian ? pntoh32(buf) : pletoh32(buf);

    // Following is the printk formats.
    // We currently don't parse them, so we discard it.
    if (!wtap_read_bytes(fh, NULL, printk_formats_len, err, err_info))
        return FALSE;
    
    return TRUE;
}

static gboolean tracecmd_parse_process_info(FILE_T fh, struct tracecmd *tracecmd, int *err, gchar **err_info)
{
    char buf[sizeof(guint64)];
    guint64 process_info_len;

    // next 4 bytes hold the length of the process information (taken from /sys/kernel/debug/tracing/saved_cmdlines)
    if (!wtap_read_bytes(fh, &buf, sizeof(guint64), err, err_info))
        return FALSE;
    process_info_len = tracecmd->big_endian ? pntoh64(buf) : pletoh64(buf);

    // Following is the process information that maps PIDs to command lines.
    // We currently don't parse it, so we discard it.
    if (!wtap_read_bytes(fh, NULL, (unsigned int)process_info_len, err, err_info))
        return FALSE;
    
    return TRUE;
}

static gboolean tracecmd_parse_options(FILE_T fh, struct tracecmd *tracecmd, int *err, gchar **err_info)
{
    char buf[sizeof(guint32)];
    guint16 option_type;
    guint32 option_size;

    // keep reading options until encountering option type 0
    while (TRUE) {
        // next 2 bytes hold the option type
        if (!wtap_read_bytes(fh, &buf, sizeof(guint16), err, err_info))
            return FALSE;
        option_type = tracecmd->big_endian ? pntoh16(buf) : pletoh16(buf);

        // option type 0 signifies end of options
        if (option_type == 0)
            return TRUE;
        
        // next 4 bytes hold the option size
        if (!wtap_read_bytes(fh, &buf, sizeof(guint32), err, err_info))
            return FALSE;
        option_size = tracecmd->big_endian ? pntoh32(buf) : pletoh32(buf);

        // Next comes the option data.
        // We currently don't handle any options so we discard it.
        if (!wtap_read_bytes(fh, NULL, option_size, err, err_info))
            return FALSE;
    }
}

static gboolean tracecmd_parse_flyrecord(FILE_T fh, struct tracecmd *tracecmd, int *err, gchar **err_info)
{
    guint32 i;
    char buf[sizeof(guint64)];

    // allocate array of cpu_data structs
    tracecmd->cpu_data = g_new0(struct cpu_data, tracecmd->num_cpus);

    // for each CPU execute the following
    for (i = 0; i < tracecmd->num_cpus; i++) {
        // next 8 bytes hold the file offset of the data for this CPU
        if (!wtap_read_bytes(fh, &buf, sizeof(guint64), err, err_info))
            return FALSE;
        tracecmd->cpu_data[i].offset = tracecmd->big_endian ? pntoh64(buf) : pletoh64(buf);

        // next 8 bytes hold the size of the data for this CPU
        if (!wtap_read_bytes(fh, &buf, sizeof(guint64), err, err_info))
            return FALSE;
        tracecmd->cpu_data[i].size = tracecmd->big_endian ? pntoh64(buf) : pletoh64(buf);

        ws_debug("%lu bytes of data (%lu pages) for CPU %u are located at offset 0x%08lx",
            tracecmd->cpu_data[i].size, tracecmd->cpu_data[i].size / tracecmd->page_size,
            i, tracecmd->cpu_data[i].offset);
    }

    return TRUE;
}

static gboolean tracecmd_parse_header_end(FILE_T fh, struct tracecmd *tracecmd, int *err, gchar **err_info)
{
    char buf[10]; // enough to hold "options  \0", "latency  \0" or "flyrecord\0"

    const char options[] = "options  ", latency[] = "latency  ", flyrecord[] = "flyrecord";

    // next 4 bytes hold the number of CPUs
    if (!wtap_read_bytes(fh, &buf, sizeof(guint32), err, err_info))
        return FALSE;
    tracecmd->num_cpus = tracecmd->big_endian ? pntoh32(buf) : pletoh32(buf);

    // make sure there are more than 0 CPUs
    if (tracecmd->num_cpus == 0) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("Invalid CPU count of 0");
        return FALSE;
    }

    ws_debug("%u CPUs are present on the traced system", tracecmd->num_cpus);

    // next 10 bytes hold a string representing the next data - either "options  \0", "latency  \0" or "flyrecord\0"
    if (!wtap_read_bytes(fh, &buf, 10, err, err_info))
        return FALSE;
    
    // next data is options
    if (!memcmp((void *)buf, (void *)&options, 10)) {
        if (!tracecmd_parse_options(fh, tracecmd, err, err_info))
            return FALSE;
        
        // next 10 bytes hold a string representing the next data - either "latency  \0" or "flyrecord\0"
        if (!wtap_read_bytes(fh, &buf, 10, err, err_info))
            return FALSE;
    }

    // next data is latency (text trace data) - we don't support this type of data
    if (!memcmp((void *)buf, (void *)&latency, 10)) {
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = g_strdup("Unsupported \"latency\" data");
        return FALSE;
    }
    
    // next data is flyrecord (CPU data info)
    if (!memcmp((void *)buf, (void *)&flyrecord, 10)) {
        if (!tracecmd_parse_flyrecord(fh, tracecmd, err, err_info))
            return FALSE;
    }
    else {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("No \"flyrecord\" section");
        return FALSE;
    }

    return TRUE;
}

static gboolean tracecmd_parse_headers(FILE_T fh, struct tracecmd *tracecmd, int *err, gchar **err_info)
{
    if (!tracecmd_parse_initial(fh, tracecmd, err, err_info))
        return FALSE;
    
    if (!tracecmd_parse_header_info(fh, tracecmd, err, err_info))
        return FALSE;
    
    if (!tracecmd_parse_ftrace_events(fh, tracecmd, err, err_info))
        return FALSE;
    
    if (!tracecmd_parse_events(fh, tracecmd, err, err_info))
        return FALSE;
    
    if (!tracecmd_parse_kallsyms(fh, tracecmd, err, err_info))
        return FALSE;
    
    if (!tracecmd_parse_printk_formats(fh, tracecmd, err, err_info))
        return FALSE;
    
    if (!tracecmd_parse_process_info(fh, tracecmd, err, err_info))
        return FALSE;
    
    if (!tracecmd_parse_header_end(fh, tracecmd, err, err_info))
        return FALSE;
    
    return TRUE;
}

struct rb_record_header {
    guint32 type_len:5, time_delta:27;
};

/*
 * Taken from include/linux/ring_buffer.h
 */
enum ring_buffer_type {
	RINGBUF_TYPE_DATA_TYPE_LEN_MAX = 28,
	RINGBUF_TYPE_PADDING,
	RINGBUF_TYPE_TIME_EXTEND,
	RINGBUF_TYPE_TIME_STAMP,
};

static inline guint64 next_page(guint64 offset, guint32 page_size)
{
    return offset - (offset % page_size) + page_size;
}

struct event_info {
    guint64 offset;
    guint32 size;
    guint64 ts;
    guint32 cpu;
};

enum get_record_result {
    GET_RECORD_RESULT_EVENT,
    GET_RECORD_RESULT_NOT_EVENT,
    GET_RECORD_RESULT_END_OF_PAGE,
    GET_RECORD_RESULT_ERROR,
};

/**
 * Get a single record from the file,
 * while making sure we are not exceeding the current page boundaries.
 * This function relies on a state set by tracecmd_read
 * and should not be used by any other function.
*/
static inline enum get_record_result __tracecmd_get_record(FILE_T fh, struct tracecmd *tracecmd, struct event_info *event_info, int *err, gchar **err_info)
{
    char buf[sizeof(guint64)];
    struct rb_record_header header;
    guint32 len, size, time_delta_high;
    struct rb_iter_state *state = (struct rb_iter_state *)&tracecmd->state;
    guint64 offset = (guint64)file_tell(fh);

    // we are at the beginning of the current page - read the header and set the current timestamp
    if (offset == state->current_page) {
        // next 8 bytes are the page timestamp
        if (!wtap_read_bytes(fh, &buf, sizeof(guint64), err, err_info))
            return GET_RECORD_RESULT_ERROR;
        state->current_ts = tracecmd->big_endian ? pntoh64(buf) : pletoh64(buf);

        // next sizeof(local_t) bytes are discarded
        // (this is the kernel long size, which is assumed to be the same as the user long size)
        if (!wtap_read_bytes(fh, NULL, tracecmd->long_size, err, err_info))
            return GET_RECORD_RESULT_ERROR;
        
        offset = (guint64)file_tell(fh);
    }

    // make sure we can read a full record header without reaching the end of the page
    if (offset + sizeof(header) > next_page(state->current_page, tracecmd->page_size))
        return GET_RECORD_RESULT_END_OF_PAGE;
    
    // read the record header
    if (!wtap_read_bytes(fh, &header, sizeof(header), err, err_info))
        return GET_RECORD_RESULT_ERROR;
    
    offset = (guint64)file_tell(fh);
    
    ws_noisy("record at offset 0x%08lx: type_len=%u, time_delta=%u", offset, header.type_len, header.time_delta);

    switch (header.type_len) {
        case RINGBUF_TYPE_TIME_STAMP:
            *err = WTAP_ERR_UNSUPPORTED;
            *err_info = g_strdup("Unsupported timestamp record found");
            return GET_RECORD_RESULT_ERROR;
        
        case RINGBUF_TYPE_PADDING:
            *err = WTAP_ERR_UNSUPPORTED;
            *err_info = g_strdup("Unsupported padding record found");
            return GET_RECORD_RESULT_ERROR;
        
        case RINGBUF_TYPE_TIME_EXTEND:
            // next 4 bytes contain bits 28-59 of the time delta
            if (!wtap_read_bytes(fh, &buf, sizeof(guint32), err, err_info))
                return GET_RECORD_RESULT_ERROR;
            time_delta_high = tracecmd->big_endian ? pntoh32(buf) : pletoh32(buf);
            state->current_ts += (time_delta_high << 27) + header.time_delta;

            return GET_RECORD_RESULT_NOT_EVENT;
        
        // data record
        default:
            state->current_ts += header.time_delta;

            // the length is stored separately
            if (header.type_len == 0) {
                // make sure we can read the length without exceeding the page boundaries
                if (offset + sizeof(guint32) > next_page(state->current_page, tracecmd->page_size))
                    return GET_RECORD_RESULT_END_OF_PAGE;
                
                // next 4 bytes are the actual length
                if (!wtap_read_bytes(fh, &buf, sizeof(guint32), err, err_info))
                    return GET_RECORD_RESULT_ERROR;
                len = tracecmd->big_endian ? pntoh32(buf) : pletoh32(buf);

                offset = (guint64)file_tell(fh);

                // length of 0 means no more events on this page
                if (len == 0)
                    return GET_RECORD_RESULT_END_OF_PAGE;
                
                ws_noisy("actual length is %u", len);
                size = len - 4; // length includes the 4 byte length value which was read
            }

            else
                size = header.type_len * 4; // length is in 4-byte words
            
            // make sure the length does not exceed the page boundaries
            if (offset + size > next_page(state->current_page, tracecmd->page_size))
                return GET_RECORD_RESULT_END_OF_PAGE;
            
            // set up event info
            event_info->offset = offset;
            event_info->size = size;
            event_info->ts = state->current_ts;
            event_info->cpu = state->current_cpu;
            
            return GET_RECORD_RESULT_EVENT;
    }
}

static void set_rec_metadata(struct tracecmd *tracecmd, wtap_rec *rec, struct event_info *event_info)
{
    struct event_options *options;

    rec->rec_type = REC_TYPE_FT_SPECIFIC_EVENT;
    rec->rec_header.ft_specific_header.record_type = BLOCK_TYPE_EVENT;
    rec->rec_header.ft_specific_header.record_len = event_info->size;
    rec->ts.secs = (time_t)(event_info->ts / 1000000000);
    rec->ts.nsecs = (int)(event_info->ts % 1000000000);
    rec->presence_flags = WTAP_HAS_TS;

    ws_buffer_assure_space(&rec->options_buf, sizeof(struct event_options));
    options = (struct event_options *)ws_buffer_start_ptr(&rec->options_buf);
    memset(options, 0, sizeof(*options));
    options->machine_id = machine_id;
    options->event_type = EVENT_TYPE_LINUX_TRACE_EVENT;
    options->type_specific_options.linux_trace_event.big_endian = tracecmd->big_endian;
    options->type_specific_options.linux_trace_event.cpu = event_info->cpu;
}

/**
 * Read the next event from the file.
 * Each CPU has it's own set of events,
 * so we go through the CPUs by order and read their events.
 * 
 * The data of each CPU is a set of sequentially stored pages,
 * starting with a page header and the followed by the events.
 * 
 * Currently we parse the header according to what we know about it,
 * and not according to its format that is stored in the file
 * (taken from /sys/kernel/debug/tracing/events/header_page).
 * This means we make 3 important assumptions:
 * - The general header format is not changed
 * - The kernel long size is the same as the user long size
 * - The page size stored in the file header was reported correctly
 * These assumptions may be false, so TODO we need to actually use the header format.
*/
static gboolean tracecmd_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info, gint64 *data_offset)
{
    enum get_record_result res;
    struct tracecmd *tracecmd = (struct tracecmd *)wth->priv;
    struct rb_iter_state *state = (struct rb_iter_state *)&tracecmd->state;
    struct cpu_data current_cpu_data = tracecmd->cpu_data[state->current_cpu];
    struct event_info *event_info = g_new0(struct event_info, 1);

    do {
        res = __tracecmd_get_record(wth->fh, tracecmd, event_info, err, err_info);

        switch (res) {
            case GET_RECORD_RESULT_ERROR:
                goto error;
            
            // go to next page
            case GET_RECORD_RESULT_END_OF_PAGE:                
                // make sure we haven't reached the end of the data for this CPU
                if (next_page(state->current_page, tracecmd->page_size) >= current_cpu_data.offset + current_cpu_data.size) {
                    // last CPU, no more events
                    if (state->current_cpu + 1 >= tracecmd->num_cpus)
                        goto error;
                    
                    // go to next CPU
                    current_cpu_data = tracecmd->cpu_data[++state->current_cpu];
                    state->current_page = current_cpu_data.offset;
                    ws_noisy("moved to CPU %u", state->current_cpu);
                }

                else
                    state->current_page = next_page(state->current_page, tracecmd->page_size);
                
                // seek to page
                if (file_seek(wth->fh, state->current_page, SEEK_SET, err) == -1)
                    goto error;
                ws_noisy("moved to page at offset 0x%08lx", state->current_page);
                break;
            
            default:
                break;
        }
    }
    while (res != GET_RECORD_RESULT_EVENT);

    ws_noisy("found event: offset=0x%08lx size=%u ts=%lu", event_info->offset, event_info->size, event_info->ts);

    // read the event data
    if (!wtap_read_packet_bytes(wth->fh, buf, event_info->size, err, err_info))
        goto error;
    
    set_rec_metadata(tracecmd, rec, event_info);
    *data_offset = event_info->offset;

    // insert event info into map
    g_hash_table_insert(tracecmd->events, &event_info->offset, event_info);

    return TRUE;

error:
    g_free(event_info);
    return FALSE;
}

static gboolean tracecmd_seek_read(wtap *wth, gint64 seek_off, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info)
{
    struct tracecmd *tracecmd = (struct tracecmd *)wth->priv;
    struct event_info *event_info;

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return FALSE;

    ws_noisy("getting event at offset 0x%08lx", seek_off);
    
    // lookup event info
    if ((event_info = g_hash_table_lookup(tracecmd->events, &seek_off)) == NULL)
        return FALSE;
    
    // read the event data
    if (!wtap_read_packet_bytes(wth->random_fh, buf, event_info->size, err, err_info))
        return FALSE;
    
    set_rec_metadata(tracecmd, rec, event_info);

    return TRUE;
}

/**
 * Free all the allocations we made.
 * The allocation we made for struct tracecmd, referenced by wth->priv,
 * is freed automatically by Wireshark.
*/
static void tracecmd_close(wtap *wth)
{
    struct tracecmd *tracecmd = (struct tracecmd *)wth->priv;

    for (int i = 0; i <= MAX_EVENT; i++) {
        if (tracecmd->event_formats[i])
            tracecmd_free_event_format(tracecmd->event_formats[i]);
    }

    g_free(tracecmd->cpu_data);
    g_hash_table_destroy(tracecmd->events);
}

wtap_open_return_val tracecmd_open(wtap *wth, int *err, gchar **err_info)
{
    unsigned char buf[sizeof(tracecmd_magic)];
    struct tracecmd *tracecmd;

    if (!wtap_read_bytes(wth->fh, &buf, sizeof(buf), err, err_info)) {
        // EOF
        if (*err == 0)
            return WTAP_OPEN_NOT_MINE;
        return WTAP_OPEN_ERROR;
    }

    if (memcmp(&buf, tracecmd_magic, sizeof(buf)) != 0)
        return WTAP_OPEN_NOT_MINE;

    ws_debug("trace-cmd magic found");

    // read file headers
    tracecmd = g_new0(struct tracecmd, 1);
    if (!tracecmd_parse_headers(wth->fh, tracecmd, err, err_info))
        return WTAP_OPEN_ERROR;
    
    // initialize event iteration state
    tracecmd->state.current_cpu = 0;
    tracecmd->state.current_page = tracecmd->cpu_data[0].offset;
    if (file_seek(wth->fh, tracecmd->state.current_page, SEEK_SET, err) == -1)
        return WTAP_OPEN_ERROR;
    
    // initialize mapping from event offset to info
    tracecmd->events = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
    
    wth->file_type_subtype = tracecmd_file_type_subtype;
    wth->subtype_read = tracecmd_read;
    wth->subtype_seek_read = tracecmd_seek_read;
    wth->subtype_close = tracecmd_close;
    wth->file_encap = WTAP_ENCAP_TRACESHARK;
    wth->file_tsprec = WTAP_TSPREC_NSEC;
    wth->snapshot_length = 0;
    wth->priv = tracecmd;

    // initialize map of machine IDs to event formats for that machine,
    // and populate it with the (only) machine for this file.
    wth->linux_trace_event_formats = g_hash_table_new(g_int_hash, g_int_equal);
    g_hash_table_insert(wth->linux_trace_event_formats, (gpointer)&machine_id, &tracecmd->event_formats);

    // add generated IDB (required so the file can be written as pcapng)
    wtap_add_generated_idb(wth);

    return WTAP_OPEN_MINE;
}

/*
 * Wiretap doesn't allow us to have a file type that doesn't support any blocks.
 * We indicate support for packet blocks even though we make no use of them.
 */
static const struct supported_block_type tracecmd_blocks_supported[] = {
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info tracecmd_info = {
    "Ftrace trace-cmd", "trace-cmd", "dat", NULL,
    FALSE, BLOCKS_SUPPORTED(tracecmd_blocks_supported),
    NULL, NULL, NULL
};

void register_tracecmd(void)
{
    tracecmd_file_type_subtype = wtap_register_file_type_subtype(&tracecmd_info);
}