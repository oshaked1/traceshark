#include "wtap.h"

#ifndef __TRACECMD_H__
#define __TRACECMD_H__

struct linux_trace_event_options {
    gboolean big_endian;
    guint32 cpu;
};

struct linux_trace_event_field {
    struct linux_trace_event_field *next;
    gchar *full_definition;
    gchar *type;
    gboolean is_array;
    gchar *name;
    guint32 length;             // array length for array type fields
    gchar *length_expression;   // array length expression for array type fields (if this is set, length is not set)
    guint32 offset;
    guint32 size;
    guint32 is_signed;
    gboolean is_data_loc;
    gboolean is_variable_data;
    struct linux_trace_event_field *data_field;
};

struct linux_trace_event_format {
    gchar *system, *name;
    guint16 id;
    struct linux_trace_event_field *fields;
    gchar *print_fmt;
};

WS_DLL_PUBLIC int tracecmd_get_file_type_subtype(void);

wtap_open_return_val tracecmd_open(wtap *wth, int *err, gchar **err_info);

struct linux_trace_event_format **tracecmd_parse_event_formats_buf(const Buffer *format_data, gboolean byte_swapped);

void tracecmd_free_event_formats(struct linux_trace_event_format **event_formats);

#endif /* __TRACECMD_H__ */