#include "traceshark.h"
#include <wiretap/traceshark.h>

const value_string traceshark_event_types[] = {
    { EVENT_TYPE_UNKNOWN, "Unknown" },
    { EVENT_TYPE_LINUX_TRACE_EVENT, "Linux Trace Event" },
    { 0, "NULL" }
};

wmem_map_t *subscribed_fields = NULL;
wmem_map_t *subscribed_field_values = NULL;

static void free_values(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
    fvalue_t *fv;
    guint i;
    wmem_array_t *arr = (wmem_array_t *)value;

    for (i = 0; i < wmem_array_get_count(arr); i++) {
        fv = *((fvalue_t **)wmem_array_index(arr, i));
        fvalue_free(fv);
    }
}

static gboolean subscribed_field_values_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data _U_)
{
    wmem_map_foreach(subscribed_field_values, free_values, NULL);

    // return TRUE so this callback isn't unregistered
    return TRUE;
}

void traceshark_register_field_subscription(gchar *filter_name)
{
    gchar *key;

    ws_debug("registering subscription for field %s", filter_name);

    // make sure subscribed fields map exists
    if (subscribed_fields == NULL) {
        subscribed_fields = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
        subscribed_field_values = wmem_map_new_autoreset(wmem_epan_scope(), wmem_packet_scope(), g_str_hash, g_str_equal);
        wmem_register_callback(wmem_packet_scope(), subscribed_field_values_destroy_cb, NULL);
    }
    
    // add field to subscription map
    key = wmem_alloc(wmem_epan_scope(), strlen(filter_name) + 1);
    strcpy(key, filter_name);
    wmem_map_insert(subscribed_fields, key, NULL);
}

wmem_array_t *traceshark_fetch_subscribed_field_values(gchar *filter_name)
{
    return wmem_map_lookup(subscribed_field_values, filter_name);
}

fvalue_t *traceshark_fetch_subscribed_field_single_value(gchar *filter_name)
{
    wmem_array_t *values = traceshark_fetch_subscribed_field_values(filter_name);

    if (values && wmem_array_get_count(values) >= 1)
        return *((fvalue_t **)wmem_array_index(values, 0));
    
    return NULL;
}

static gboolean has_subscription(header_field_info *hf)
{
    // make sure subscribed fields map exists
    if (subscribed_fields == NULL || subscribed_field_values == NULL)
        return FALSE;
    
    // make sure this field has a filter string (subscriptions are based off this string)
    if (!hf || !hf->abbrev)
        return FALSE;
    
    // check if there is a subscription for this field
    return wmem_map_contains(subscribed_fields, hf->abbrev);
}

#define traceshark_handle_field_subscription(hfindex, value, fvalue_set_func) \
    /* get field info */ \
    header_field_info *_hf = proto_registrar_get_nth(hfindex); \
    \
    /* make sure there is a subscription for this field */ \
    if (has_subscription(_hf)) { \
        \
        /* create value */ \
        fvalue_t *_fv = fvalue_new(_hf->type); \
        fvalue_set_func(_fv, value); \
        \
        /* check if a value for this field was added already */ \
        wmem_array_t *_values = wmem_map_lookup(subscribed_field_values, _hf->abbrev); \
        \
        /* lookup succeeded - add this value to the value list for this subscription */ \
        if (_values) \
            wmem_array_append_one(_values, _fv); \
        /* lookup failed - create new value array and insert it into the subscribed values map */ \
        else { \
            _values = wmem_array_new(wmem_packet_scope(), sizeof(fvalue_t *)); \
            wmem_array_append_one(_values, _fv); \
            wmem_map_insert(subscribed_field_values, _hf->abbrev, _values); \
        } \
    }

proto_item *traceshark_proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb, const gint start, gint length, const guint encoding)
{
    header_field_info *hf;
    fvalue_t *fv;
    union {
        guint32 u32;
        gint32 s32;
        guint64 u64;
        gint64 s64;
        gfloat flt;
        gdouble dbl;
        guint8 *buf;
    } val;
    gint reported_len;
    wmem_strbuf_t *strbuf;
    wmem_array_t *values;
    proto_item *item = proto_tree_add_item(tree, hfindex, tvb, start, length, encoding);
    
    hf = proto_registrar_get_nth(hfindex);

    if (!has_subscription(hf))
        return item;

    // read value according to type and size
    switch (hf->type) {
        // integer types - read as u64
        case FT_BOOLEAN:
        case FT_INT8:
        case FT_INT16:
        case FT_INT32:
        case FT_INT64:
        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT32:
        case FT_UINT64:
            switch (length) {
                case 1:
                    val.u64 = (guint64)tvb_get_guint8(tvb, start);
                    break;
                case 2:
                    val.u64 = (guint64)tvb_get_guint16(tvb, start, encoding);
                    break;
                case 4:
                    val.u64 = (guint64)tvb_get_guint32(tvb, start, encoding);
                    break;
                case 8:
                    val.u64 = tvb_get_guint64(tvb, start, encoding);
                    break;
                default:
                    DISSECTOR_ASSERT_NOT_REACHED();
            }
            break;
        case FT_FLOAT:
            val.flt = tvb_get_ieee_float(tvb, start, encoding);
            break;
        case FT_DOUBLE:
            val.dbl = tvb_get_ieee_double(tvb, start, encoding);
            break;
        case FT_STRING:
            val.buf = tvb_get_string_enc(wmem_packet_scope(), tvb, start, length, encoding);
            break;
        case FT_STRINGZ:
            val.buf = tvb_get_stringz_enc(wmem_packet_scope(), tvb, start, &reported_len, encoding);
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }

    // initialize fvalue according to type
    fv = fvalue_new(hf->type);

    switch (hf->type) {
        // signed integer up to 32-bit
        case FT_INT8:
        case FT_INT16:
        case FT_INT32:
            fvalue_set_sinteger(fv, val.s32);
            break;
        // unsigned integer up to 32-bit
        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT32:
            fvalue_set_uinteger(fv, val.u32);
            break;
        case FT_INT64:
            fvalue_set_sinteger64(fv, val.s64);
            break;
        case FT_UINT64:
        case FT_BOOLEAN:
            fvalue_set_uinteger64(fv, val.u64);
            break;
        case FT_STRING:
            strbuf = wmem_strbuf_new_len(NULL, (gchar *)val.buf, length);
            fvalue_set_strbuf(fv, strbuf);
            break;
        case FT_STRINGZ:
            fvalue_set_string(fv, (gchar *)val.buf);
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }

    // check if a value for this field was added already
    values = wmem_map_lookup(subscribed_field_values, hf->abbrev);

    // lookup succeeded - add this value to the value list for this subscription
    if (values)
        wmem_array_append_one(values, fv);
    // lookup failed - create new value array and insert it into the subscribed values map
    else {
        values = wmem_array_new(wmem_packet_scope(), sizeof(fvalue_t *));
        wmem_array_append_one(values, fv);
        wmem_map_insert(subscribed_field_values, hf->abbrev, values);
    }

    return item;
}

proto_item *traceshark_proto_tree_add_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint32 value)
{    
    traceshark_handle_field_subscription(hfindex, value, fvalue_set_uinteger);
    return proto_tree_add_uint(tree, hfindex, tvb, start, length, value);
}

proto_item *traceshark_proto_tree_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, const char* value)
{
    traceshark_handle_field_subscription(hfindex, value, fvalue_set_string);
    return proto_tree_add_string(tree, hfindex, tvb, start, length, value);
}