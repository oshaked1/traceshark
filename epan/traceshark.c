#include "traceshark.h"
#include <wiretap/traceshark.h>

wmem_map_t *subscribed_fields = NULL;
wmem_map_t *subscribed_field_values = NULL;

static void free_values_cb(gpointer key _U_, gpointer value, gpointer user_data _U_)
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
    wmem_map_foreach(subscribed_field_values, free_values_cb, NULL);

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

    // check if there is already a subscription for this field
    if (wmem_map_contains(subscribed_fields, filter_name))
        return;
    
    // add field to subscription map
    key = wmem_strdup(wmem_epan_scope(), filter_name);
    wmem_map_insert(subscribed_fields, key, NULL);
}

wmem_array_t *traceshark_subscribed_field_get_values(gchar *filter_name)
{
    return wmem_map_lookup(subscribed_field_values, filter_name);
}

fvalue_t *traceshark_subscribed_field_get_single_value_or_null(gchar *filter_name)
{
    wmem_array_t *values = traceshark_subscribed_field_get_values(filter_name);

    if (values && wmem_array_get_count(values) >= 1)
        return *((fvalue_t **)wmem_array_index(values, 0));
    
    return NULL;
}

fvalue_t *traceshark_subscribed_field_get_single_value(gchar *filter_name)
{
    fvalue_t *fv = traceshark_subscribed_field_get_single_value_or_null(filter_name);
    DISSECTOR_ASSERT_HINT(fv != NULL, wmem_strdup_printf(wmem_packet_scope(), "Could not fetch value for subscribed field %s", filter_name));
    return fv;
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

#define traceshark_handle_field_subscription(hfindex, value, fvalue_set_func) { \
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

proto_item *traceshark_proto_tree_add_int(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, gint32 value)
{
    traceshark_handle_field_subscription(hfindex, value, fvalue_set_sinteger);
    return proto_tree_add_int(tree, hfindex, tvb, start, length, value);
}

proto_item *traceshark_proto_tree_add_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint32 value)
{    
    traceshark_handle_field_subscription(hfindex, value, fvalue_set_uinteger);
    return proto_tree_add_uint(tree, hfindex, tvb, start, length, value);
}

proto_item *traceshark_proto_tree_add_int64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, gint64 value)
{
    traceshark_handle_field_subscription(hfindex, value, fvalue_set_sinteger64);
    return proto_tree_add_int64(tree, hfindex, tvb, start, length, value);
}

proto_item *traceshark_proto_tree_add_uint64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint64 value)
{
    traceshark_handle_field_subscription(hfindex, value, fvalue_set_uinteger64);
    return proto_tree_add_uint64(tree, hfindex, tvb, start, length, value);
}

proto_item *traceshark_proto_tree_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, const char* value)
{
    traceshark_handle_field_subscription(hfindex, value, fvalue_set_string);
    return proto_tree_add_string(tree, hfindex, tvb, start, length, value);
}

struct process_event {
    struct traceshark_process *process; /* Process information as it was after the event occurred */
    enum process_event_type event_type;
    union {
        const struct fork_event *fork;
    } event;
};

#define PID_LIFECYCLE_KEY(machine_id, pid) (((guint64)(machine_id) << 32) + (pid.raw))

// map of machine ID and PID to PID lifecycle events
wmem_map_t *pid_lifecycles = NULL;

/**
 * @brief Walk the events in a PID lifecycle backwards, starting from a given node.
 * 
 * @param curr_node (in, out) The starting node (will be changed to the current node with each iteration!)
 * @param curr_event (out) The current event for this iteration
 */
#define lifecycle_events_walk_backwards(curr_node, curr_event) \
    for (curr_node = g_tree_node_previous(curr_node), curr_event = curr_node != NULL ? g_tree_node_value(curr_node) : NULL; curr_event != NULL; curr_node = g_tree_node_previous(curr_node), curr_event = curr_node != NULL ? g_tree_node_value(curr_node) : NULL)

/**
 * @brief Walk the events in a PID lifecycle forwards, starting from a given node.
 * 
 * @param curr_node (in, out) The starting node (will be changed to the current node with each iteration!)
 * @param curr_event (out) The current event for this iteration
 */
#define lifecycle_events_walk_forwards(curr_node, curr_event) \
    for (curr_node = g_tree_node_next(curr_node), curr_event = curr_node != NULL ? g_tree_node_value(curr_node) : NULL; curr_event != NULL; curr_node = g_tree_node_next(curr_node), curr_event = curr_node != NULL ? g_tree_node_value(curr_node) : NULL)

static void destroy_lifecycle_cb(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
    g_tree_destroy((GTree *)value);
}

static gboolean pid_lifecycles_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data _U_)
{
    wmem_map_foreach(pid_lifecycles, destroy_lifecycle_cb, NULL);

    // return TRUE so this callback isn't unregistered
    return TRUE;
}

static struct traceshark_process *generate_empty_process_info(wmem_allocator_t *allocator, union pid pid)
{
    struct traceshark_process *process = wmem_new0(allocator, struct traceshark_process);
    process->pid = pid;
    return process;
}

static const struct process_event *get_preceding_event(GTree *lifecycle, const nstime_t *ts)
{
    GTreeNode *res;

    // lower bound returns the first entry that has an equal or larger ts,
    // and its previous entry will be the last one before our ts.
    if ((res = g_tree_lower_bound(lifecycle, ts)) != NULL) {
        if ((res = g_tree_node_previous(res)) != NULL)
            return (struct process_event *)g_tree_node_value(res);
        
        // no previous entry
        return NULL;
    }

    // no lower bound, the last entry will be before our ts
    if ((res = g_tree_node_last(lifecycle)) != NULL)
        return (struct process_event *)g_tree_node_value(res);
    
    // no last entry, which means the tree is empty (this shouldn't happen but we don't care if it does)
    return NULL;
}

const struct traceshark_process *traceshark_get_process_info(guint32 machine_id, union pid pid, const nstime_t *ts)
{
    guint64 key;
    GTree *lifecycle;
    const struct process_event *event;

    // check if PID lifecycles map is initialized
    if (pid_lifecycles == NULL)
        return generate_empty_process_info(wmem_packet_scope(), pid);

    // lookup the PID lifecycle tree
    key = PID_LIFECYCLE_KEY(machine_id, pid);
    if ((lifecycle = wmem_map_lookup(pid_lifecycles, &key)) == NULL)
        return generate_empty_process_info(wmem_packet_scope(), pid);
    
    /**
     * Try finding a lifecycle event that happened at the same time as the given ts.
     * If no such event exists, get the last event that happened before it.
     * If that doesn't exist, generate an empty process struct.
     * If an appropriate lifecycle event is found, return the associated process struct.
     */
    if ((event = g_tree_lookup(lifecycle, ts)) != NULL)
        return event->process;
    
    if ((event = get_preceding_event(lifecycle, ts)) != NULL)
        return event->process;
    
    return generate_empty_process_info(wmem_packet_scope(), pid);
}

static struct fork_event *duplicate_fork_event(const struct fork_event *src)
{
    struct fork_event *dst = wmem_new0(wmem_file_scope(), struct fork_event);

    dst->parent_pid = src->parent_pid;
    dst->child_pid = src->child_pid;

    if (src->child_name != NULL)
        dst->child_name = wmem_strdup(wmem_file_scope(), src->child_name);

    return dst;
}

static struct traceshark_process *duplicate_process_info(const struct traceshark_process *src)
{
    struct traceshark_process *dst = wmem_new0(wmem_file_scope(), struct traceshark_process);

    dst->pid = src->pid;
    
    if (src->name != NULL)
        dst->name = wmem_strdup(wmem_file_scope(), src->name);
    
    return dst;
}

static const char pid_lifecycle_update_err[] = "Cannot update PID lifecycle - event already exists for this exact timestamp";

static const struct traceshark_process *update_process_fork_parent(GTree *lifecycle, const nstime_t *ts, const struct fork_event *info)
{
    struct process_event *event;
    const struct process_event *prev_event, *curr_event;
    nstime_t *ts_copy;
    GTreeNode *event_node, *curr_node;
    gboolean stop;

    // make sure there's no event with the same ts
    DISSECTOR_ASSERT_HINT(g_tree_lookup(lifecycle, ts) == NULL, pid_lifecycle_update_err);

    // create event
    event = wmem_new(wmem_file_scope(), struct process_event);
    event->event_type = PROCESS_FORK;
    event->event.fork = duplicate_fork_event(info);

    // insert event into the lifecycle tree
    ts_copy = wmem_new(wmem_file_scope(), nstime_t);
    nstime_copy(ts_copy, ts);
    event_node = g_tree_insert_node(lifecycle, ts_copy, event);

    // get process info from last event
    prev_event = get_preceding_event(lifecycle, ts);

    // make sure previous event is not a process exit, which invalidates everything we know about the process
    if (prev_event != NULL && prev_event->event_type != PROCESS_EXIT)
        event->process = duplicate_process_info(prev_event->process);

    // no previous event, or previous event was a process exit - generate new process info
    else
        event->process = generate_empty_process_info(wmem_file_scope(), info->parent_pid);

    // Assume the parent's name is the same as the child's name.
    // If they don't match, update the parent's name and propagate it.
    if (info->child_name != NULL && (event->process->name == NULL || strcmp(event->process->name, info->child_name) != 0)) {
        event->process->name = wmem_strdup(wmem_file_scope(), info->child_name);

        // propagate name backwards (this makes sense because it's not a new piece of information from this event)
        curr_node = event_node;
        lifecycle_events_walk_backwards(curr_node, curr_event) {
            // stop propagating if we hit the end of a previous process, or an event that changes the process name
            stop = FALSE;
            switch (curr_event->event_type) {
                case PROCESS_EXIT:
                case PROCESS_EXEC:
                case PROCESS_FORK:
                    stop = TRUE;
                    break;
            }
            if (stop)
                break;
            
            curr_event->process->name = wmem_strdup(wmem_file_scope(), event->process->name);
        }

        // propagate name forwards
        curr_node = event_node;
        lifecycle_events_walk_forwards(curr_node, curr_event) {
            // stop propagating if we hit an event that changes the process name
            stop = FALSE;
            switch (curr_event->event_type) {
                case PROCESS_EXEC:
                case PROCESS_FORK:
                    stop = TRUE;
                    break;
            }
            if (stop)
                break;
            
            curr_event->process->name = wmem_strdup(wmem_file_scope(), event->process->name);

            // stop propagating if this event was the end of the process
            if (curr_event->event_type == PROCESS_EXIT)
                break;
        }
    }

    return event->process;
}

static void update_process_fork_child(GTree *lifecycle, const nstime_t *ts, const struct fork_event *info)
{
    struct process_event *event;
    nstime_t *ts_copy;
    GTreeNode *event_node, *curr_node;
    const struct process_event *curr_event;
    gboolean stop;

    // make sure there's no event with the same ts
    DISSECTOR_ASSERT_HINT(g_tree_lookup(lifecycle, ts) == NULL, pid_lifecycle_update_err);

    // create event
    event = wmem_new(wmem_file_scope(), struct process_event);
    event->event_type = PROCESS_FORK;
    event->event.fork = duplicate_fork_event(info);

    // create new process info
    event->process = generate_empty_process_info(wmem_file_scope(), event->event.fork->child_pid);
    event->process->name = wmem_strdup(wmem_file_scope(), info->child_name);

    // insert event into the lifecycle tree
    ts_copy = wmem_new(wmem_file_scope(), nstime_t);
    nstime_copy(ts_copy, ts);
    event_node = g_tree_insert_node(lifecycle, ts_copy, event);

    // propagate name forwards
    curr_node = event_node;
    lifecycle_events_walk_forwards(curr_node, curr_event) {
        // stop propagating if we hit an event that changes the process name
        stop = FALSE;
        switch (curr_event->event_type) {
            case PROCESS_EXEC:
            case PROCESS_FORK:
                stop = TRUE;
                break;
        }
        
        curr_event->process->name = wmem_strdup(wmem_file_scope(), event->process->name);

        // stop propagating if this event was the end of the process
        if (curr_event->event_type == PROCESS_EXIT)
            break;
    }
}

const struct traceshark_process *traceshark_update_process_fork(guint32 machine_id, union pid pid, const nstime_t *ts, const struct fork_event *info)
{
    guint64 key;
    guint64 *pkey;
    GTree *lifecycle;
    const struct traceshark_process *process;

    // make sure PID lifecycles map is initialized
    if (pid_lifecycles == NULL) {
        pid_lifecycles = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_int64_hash, g_int64_equal);
        wmem_register_callback(wmem_file_scope(), pid_lifecycles_destroy_cb, NULL);
    }

    // first update the parent PID's lifecycle
    key = PID_LIFECYCLE_KEY(machine_id, pid);
    lifecycle = wmem_map_lookup(pid_lifecycles, (gpointer)&key);

    // parent lifecycle doens't exist - create it
    if (lifecycle == NULL) {
        lifecycle = g_tree_new(nstime_cmp);
        pkey = wmem_new(wmem_file_scope(), guint64);
        *pkey = key;
        wmem_map_insert(pid_lifecycles, pkey, lifecycle);
    }

    process = update_process_fork_parent(lifecycle, ts, info);

    // now update the child PID's lifecycle
    key = PID_LIFECYCLE_KEY(machine_id, info->child_pid);
    lifecycle = wmem_map_lookup(pid_lifecycles, (gpointer)&key);

    // child lifecycle doens't exist - create it
    if (lifecycle == NULL) {
        lifecycle = g_tree_new(nstime_cmp);
        pkey = wmem_new(wmem_file_scope(), guint64);
        *pkey = key;
        wmem_map_insert(pid_lifecycles, pkey, lifecycle);
    }

    update_process_fork_child(lifecycle, ts, info);

    return process;
}