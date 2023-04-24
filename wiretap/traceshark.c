#include "traceshark.h"
#include "pcapng.h"
#include "pcapng_module.h"
#include "wtap-int.h"
#include "trace-cmd.h"

// event block options
enum event_block_options {
    OPT_EB_BIG_ENDIAN = 1,
    OPT_EB_CPU
};

struct traceshark_event_block {
    guint32 machine_id;
    guint16 event_type;
    guint32 event_size;
    guint64 timestamp;
    /* ... Event Data ... */
    /* ... Padding ... */
    /* ... Options ... */
};

struct traceshark_event_format_block {
    guint32 machine_id;
    guint16 event_type;
    guint32 formats_size;
    /* ... Event Formats ... */
    /* ... Padding ... */
};

// machine info block options
enum machine_info_block_options {
    OPT_MIB_HOSTNAME = 1,
    OPT_MIB_OS_TYPE,
    OPT_MIB_OS_VERSION,
    OPT_MIB_ARCH,
    OPT_MIB_NUM_CPUS
};

struct traceshark_machine_info_block {
    guint32 machine_id;
    /* ... Options ... */
};

enum option_read_result {
    OPT_READ_OK,
    OPT_READ_EOFOPT,
    OPT_READ_ERROR
};

static gboolean process_linux_trace_event_option(wtapng_block_t *wblock, struct pcapng_option_header *header, void *value, gboolean byte_swapped)
{
    struct linux_trace_event_options *options = &((struct event_options *)ws_buffer_start_ptr(&wblock->rec->options_buf))->type_specific_options.linux_trace_event;

    switch (header->type) {
        case OPT_EB_BIG_ENDIAN:
            if (header->value_length != sizeof(guint32))
                return FALSE;
            options->big_endian = (gboolean)((gint32 *)value)[0];
            if (byte_swapped)
                options->big_endian = GUINT32_SWAP_LE_BE(options->big_endian);
            return TRUE;
        
        case OPT_EB_CPU:
            if (header->value_length != sizeof(guint32))
                return FALSE;
            options->cpu = ((guint32 *)value)[0];
            if (byte_swapped)
                options->cpu = GUINT32_SWAP_LE_BE(options->cpu);
            return TRUE;
        
        default:
            return FALSE;
    }
}

static gboolean process_machine_info_option(wtapng_block_t *wblock, struct pcapng_option_header *header, void *value, gboolean byte_swapped)
{
    struct traceshark_wblock_custom_data *custom_data = (struct traceshark_wblock_custom_data *)wblock->custom_data;
    struct traceshark_machine_info_data *machine_info = (struct traceshark_machine_info_data *)custom_data->data.machine_info_data;

    switch (header->type) {
        case OPT_MIB_HOSTNAME:
            // make sure there is a null-terminator
            if (((gchar *)value)[header->value_length - 1] != 0)
                return FALSE;
            
            machine_info->hostname = g_strdup((gchar *)value);
            return TRUE;
        
        case OPT_MIB_OS_TYPE:
            if (header->value_length != sizeof(guint16))
                return FALSE;
            machine_info->os_type = ((guint16 *)value)[0];
            if (byte_swapped)
                machine_info->os_type = GUINT16_SWAP_LE_BE(machine_info->os_type);
            return TRUE;
        
        case OPT_MIB_OS_VERSION:
            // make sure there is a null-terminator
            if (((gchar *)value)[header->value_length - 1] != 0)
                return FALSE;
            
            machine_info->os_version = g_strdup((gchar *)value);
            return TRUE;
        
        case OPT_MIB_ARCH:
            if (header->value_length != sizeof(guint16))
                return FALSE;
            machine_info->arch = ((guint16 *)value)[0];
            if (byte_swapped)
                machine_info->arch = GUINT16_SWAP_LE_BE(machine_info->arch);
            return TRUE;
        
        case OPT_MIB_NUM_CPUS:
            if (header->value_length != sizeof(guint32))
                return FALSE;
            machine_info->num_cpus = ((guint32 *)value)[0];
            if (byte_swapped)
                machine_info->num_cpus = GUINT32_SWAP_LE_BE(machine_info->num_cpus);
            return TRUE;
        
        default:
            return FALSE;
    }
}

static gboolean process_option(wtapng_block_t *wblock, struct pcapng_option_header *header, void *value, gboolean byte_swapped, guint16 event_type)
{
    switch (wblock->type) {
        case BLOCK_TYPE_EVENT:
            switch (event_type) {
                case EVENT_TYPE_LINUX_TRACE_EVENT:
                    return process_linux_trace_event_option(wblock, header, value, byte_swapped);
                default:
                    ws_debug("could not process event option for unknown event type %u", event_type);
                    return FALSE;
            }
        
        case BLOCK_TYPE_MACHINE_INFO:
            return process_machine_info_option(wblock, header, value, byte_swapped);
        
        default:
            ws_debug("could not process option for unknown block type %u", wblock->type);
            return FALSE;
    }
}

static enum option_read_result read_option(FILE_T fh, guint32 *remaining, gboolean byte_swapped, wtapng_block_t *wblock, guint16 event_type, int *err, gchar **err_info)
{
    struct pcapng_option_header header;
    void *buf;
    guint pad_size;

    // make sure we can read the option header
    if (sizeof(header) > *remaining) {
        *err_info = g_strdup_printf("traceshark: remaining block length %u is less than the option header size", *remaining);
        goto error;
    }

    // read the option header
    if (!wtap_read_bytes(fh, &header, sizeof(header), err, err_info))
        return OPT_READ_ERROR;
    *remaining -= sizeof(header);
    
    // fix byte order
    if (byte_swapped) {
        header.type = GUINT16_SWAP_LE_BE(header.type);
        header.value_length = GUINT16_SWAP_LE_BE(header.value_length);
    }

    ws_noisy("reading option type %u with length %u", header.type, header.value_length);

    // end of options
    if (header.type == OPT_EOFOPT)
        return OPT_READ_EOFOPT;

    // make sure we can read the option data
    if (header.value_length > *remaining) {
        *err_info = g_strdup_printf("traceshark: remaining block length %u is less than the option value length %u", *remaining, header.value_length);
        goto error;
    }

    // read option data
    buf = g_malloc(header.value_length);
    if (!wtap_read_bytes(fh, buf, header.value_length, err, err_info)) {
        g_free(buf);
        return OPT_READ_ERROR;
    }
    *remaining -= header.value_length;

    // read padding
    if (header.value_length % 4 != 0) {
        pad_size = 4 - (header.value_length % 4);
        
        // make sure we can read the padding
        if (pad_size > *remaining) {
            *err_info = g_strdup_printf("traceshark: remaining block length %u is less than the option pad size %u", *remaining, pad_size);
            goto error;
        }

        if (!wtap_read_bytes(fh, NULL, pad_size, err, err_info))
            goto error;
        *remaining -= pad_size;
    }

    // process option
    if (!process_option(wblock, &header, buf, byte_swapped, event_type)) {
        g_free(buf);
        *err_info = g_strdup_printf("traceshark: error processing option type %u for event type %u", header.type, event_type);
        goto error;
    }
    g_free(buf);

    return OPT_READ_OK;

error:
    *err = WTAP_ERR_BAD_FILE;
    return OPT_READ_ERROR;
}

static gboolean read_options(FILE_T fh, guint32 *remaining, gboolean byte_swapped, wtapng_block_t *wblock, guint16 event_type, int *err, gchar **err_info)
{
    enum option_read_result res;

    while ((res = read_option(fh, remaining, byte_swapped, wblock, event_type, err, err_info)) == OPT_READ_OK);

    return (res == OPT_READ_EOFOPT);
}

static void set_rec_metadata(wtapng_block_t *wblock, const struct traceshark_event_block *block)
{
    struct event_options *options = (struct event_options *)ws_buffer_start_ptr(&wblock->rec->options_buf);

    options->machine_id = block->machine_id;
    options->event_type = block->event_type;

    wblock->rec->rec_type = REC_TYPE_FT_SPECIFIC_EVENT;
    wblock->rec->rec_header.ft_specific_header.record_type = BLOCK_TYPE_EVENT;
    wblock->rec->rec_header.ft_specific_header.record_len = block->event_size;
    wblock->rec->ts.secs = (time_t)(block->timestamp / 1000000000);
    wblock->rec->ts.nsecs = (int)(block->timestamp % 1000000000);
    wblock->rec->presence_flags = WTAP_HAS_TS;
}

static gboolean traceshark_read_event_block(FILE_T fh, guint32 block_read, gboolean byte_swapped, wtapng_block_t *wblock, int *err, gchar **err_info)
{
    struct traceshark_event_block block;
    guint32 pad_size;
    struct event_options *options;

    // make sure we can read a full block header
    if (sizeof(block) > block_read) {
        *err_info = g_strdup_printf("traceshark: block length %u of an EB is less than the minimum EB size %u",
                                        block_read, (guint32)sizeof(block));
        goto error;
    }

    // read the block header
    if (!wtap_read_bytes(fh, &block, sizeof(block), err, err_info))
        return FALSE;
    block_read -= sizeof(block);

    // fix byte order
    if (byte_swapped) {
        block.machine_id = GUINT32_SWAP_LE_BE(block.machine_id);
        block.event_type = GUINT16_SWAP_LE_BE(block.event_type);
        block.event_size = GUINT32_SWAP_LE_BE(block.event_size);
        block.timestamp = GUINT64_SWAP_LE_BE(block.timestamp);
    }

    if (block.event_size > 0) {
        // calculate pad size
        if ((block.event_size % 4) != 0)
            pad_size = 4 - (block.event_size % 4);
        else
            pad_size = 0;
        
        // make sure we can read the event data
        if (block.event_size + pad_size > block_read) {
            *err_info = g_strdup_printf("traceshark: remaining block length %u of an EB is less than the event size %u",
                                            block_read, block.event_size + pad_size);
            goto error;
        }

        // read the event data
        if (!wtap_read_packet_bytes(fh, wblock->frame_buffer, block.event_size, err, err_info))
            return FALSE;
        block_read -= block.event_size;
        
        // skip over padding
        if (!wtap_read_bytes(fh, NULL, pad_size, err, err_info))
            return FALSE;
        block_read -= pad_size;
    }

    // remaining block data is options
    if (block_read > 0) {
        ws_buffer_assure_space(&wblock->rec->options_buf, sizeof(struct event_options));
        options = (struct event_options *)ws_buffer_start_ptr(&wblock->rec->options_buf);
        memset(options, 0, sizeof(*options));

        if (!read_options(fh, &block_read, byte_swapped, wblock, block.event_type, err, err_info))
            return FALSE;
    }

    // make sure there is no remaining data
    if (block_read > 0) {
        *err_info = g_strdup_printf("traceshark: %u bytes of data remain after finished processing EB", block_read);
        goto error;
    }

    set_rec_metadata(wblock, &block);

    wblock->internal = FALSE;

    return TRUE;

error:
    *err = WTAP_ERR_BAD_FILE;
    return FALSE;
}

static guint32 compute_event_block_options_size(const wtap_rec *rec)
{
    guint num_options = 0;
    guint32 options_data_size = 0;
    struct event_options *metadata = (struct event_options *)ws_buffer_start_ptr(&rec->options_buf);

    switch (metadata->event_type) {
        case EVENT_TYPE_LINUX_TRACE_EVENT:
            num_options = 2;
            options_data_size = sizeof(gint32) + sizeof(guint32); // big_endian and cpu
            break;
        default:
            return 0;
    }

    return sizeof(struct pcapng_option_header) * (num_options + 1) + options_data_size;
}

static gboolean write_option(wtap_dumper *wdh, guint16 option_type, guint32 value_length, const void *value, int *err)
{
    struct pcapng_option_header header;
    guint32 zero_pad = 0;

    header.type = option_type;
    header.value_length = value_length;

    if (!wtap_dump_file_write(wdh, &header, sizeof(header), err))
        return FALSE;
    wdh->bytes_dumped += sizeof(header);
    
    if (!wtap_dump_file_write(wdh, value, value_length, err))
        return FALSE;
    wdh->bytes_dumped += value_length;

    // pad to 32-bit boundary
    if (value_length % 4 != 0) {
        if (!wtap_dump_file_write(wdh, &zero_pad, 4 - (value_length % 4), err))
            return FALSE;
        wdh->bytes_dumped += 4 - (value_length % 4);
    }

    return TRUE;
}

static gboolean write_linux_trace_event_options(wtap_dumper *wdh, const wtap_rec *rec, int *err)
{
    struct linux_trace_event_options *options;
    gint32 big_endian;

    options = &((struct event_options *)ws_buffer_start_ptr(&rec->options_buf))->type_specific_options.linux_trace_event;

    // write big_endian field
    big_endian = (gint32)options->big_endian;
    if (!write_option(wdh, OPT_EB_BIG_ENDIAN, sizeof(big_endian), &big_endian, err))
        return FALSE;
    
    // write cpu field
    if (!write_option(wdh, OPT_EB_CPU, sizeof(options->cpu), &options->cpu, err))
        return FALSE;
    
    return TRUE;
}

static gboolean write_machine_info_options(wtap_dumper *wdh, const struct traceshark_machine_info_data *machine_info, int *err)
{
    guint16 os_type, arch;

    // write hostname option
    if (machine_info->hostname != NULL) {
        if (!write_option(wdh, OPT_MIB_HOSTNAME, strlen(machine_info->hostname) + 1, machine_info->hostname, err))
            return FALSE;
    }
    
    // write os type option
    if (machine_info->os_type != OS_UNKNOWN) {
        os_type = (guint16)machine_info->os_type;
        if (!write_option(wdh, OPT_MIB_OS_TYPE, sizeof(os_type), &os_type, err))
            return FALSE;
    }

    // write os version option
    if (machine_info->os_version != NULL) {
        if (!write_option(wdh, OPT_MIB_OS_VERSION, strlen(machine_info->os_version) + 1, machine_info->os_version, err))
            return FALSE;
    }

    // write arch option
    if (machine_info->arch != ARCH_UNKNOWN) {
        arch = (guint16)machine_info->arch;
        if (!write_option(wdh, OPT_MIB_ARCH, sizeof(arch), &arch, err))
            return FALSE;
    }

    // write num cpus option
    if (machine_info->num_cpus > 0) {
        if (!write_option(wdh, OPT_MIB_NUM_CPUS, sizeof(machine_info->num_cpus), &machine_info->num_cpus, err))
            return FALSE;
    }
    
    return TRUE;
}

static gboolean write_options(wtap_dumper *wdh, guint32 block_type, const void *data, int *err)
{
    struct pcapng_option_header header;
    wtap_rec *rec;
    struct event_options *metadata;
    struct traceshark_machine_info_data *machine_info;

    switch (block_type) {
        case BLOCK_TYPE_EVENT:
            rec = (wtap_rec *)data;
            metadata = (struct event_options *)ws_buffer_start_ptr(&rec->options_buf);

            switch (metadata->event_type) {
                case EVENT_TYPE_LINUX_TRACE_EVENT:
                    if (!write_linux_trace_event_options(wdh, rec, err))
                        return FALSE;
                    break;
                default:
                    return FALSE;
            }
            break;
        
        case BLOCK_TYPE_MACHINE_INFO:
            machine_info = (struct traceshark_machine_info_data *)data;
            if (!write_machine_info_options(wdh, machine_info, err))
                return FALSE;
            break;

        default:
            return FALSE;
    }

    // write end of options
    header.type = OPT_EOFOPT;
    header.value_length = 0;
    if (!wtap_dump_file_write(wdh, &header, sizeof(header), err))
        return FALSE;
    wdh->bytes_dumped += sizeof(header);
    
    return TRUE;
}

static gboolean traceshark_write_event_block(wtap_dumper *wdh, const wtap_rec *rec, const guint8 *pd, int *err)
{
    pcapng_block_header_t bh;
    struct traceshark_event_block eb;
    guint32 pad_size, options_size;
    const guint32 zero_pad = 0;
    struct event_options *metadata;

    // calculate pad size
    if (rec->rec_header.ft_specific_header.record_len % 4 != 0)
        pad_size = 4 - rec->rec_header.ft_specific_header.record_len % 4;
    else
        pad_size = 0;
        
    
    options_size = compute_event_block_options_size(rec);

    bh.block_type = BLOCK_TYPE_EVENT;
    bh.block_total_length = sizeof(bh) + sizeof(eb) + rec->rec_header.ft_specific_header.record_len + pad_size + options_size + 4;

    // write block header
    if (!wtap_dump_file_write(wdh, &bh, sizeof(bh), err))
        return FALSE;
    wdh->bytes_dumped += sizeof(bh);

    // populate event block fields
    metadata = (struct event_options *)ws_buffer_start_ptr(&rec->options_buf);
    eb.machine_id = metadata->machine_id;
    eb.event_type = metadata->event_type;
    eb.event_size = rec->rec_header.ft_specific_header.record_len;
    eb.timestamp = (rec->ts.secs * 1000000000) + rec->ts.nsecs;

    // write event block
    if (!wtap_dump_file_write(wdh, &eb, sizeof(eb), err))
        return FALSE;
    wdh->bytes_dumped += sizeof(eb);

    // write event data
    if (!wtap_dump_file_write(wdh, pd, eb.event_size, err))
        return FALSE;
    wdh->bytes_dumped += eb.event_size;

    // write padding
    if (!wtap_dump_file_write(wdh, &zero_pad, pad_size, err))
        return FALSE;
    wdh->bytes_dumped += pad_size;

    // write options
    if (options_size != 0) {
        if (!write_options(wdh, BLOCK_TYPE_EVENT, rec, err))
            return FALSE;
    }
    
    // write block footer
    if (!wtap_dump_file_write(wdh, &bh.block_total_length, sizeof(bh.block_total_length), err))
        return FALSE;
    wdh->bytes_dumped += sizeof(bh.block_total_length);

    return TRUE;
}

void free_event_formats_cb(gpointer data)
{
    tracecmd_free_event_formats((struct linux_trace_event_format **)data);
}

gboolean traceshark_process_event_format_data(wtap *wth, guint32 machine_id, guint16 event_type, const Buffer *format_data, gboolean byte_swapped)
{
    struct linux_trace_event_format **linux_trace_event_formats = NULL;
    guint32 *pmachine_id;

    switch (event_type) {
        case EVENT_TYPE_LINUX_TRACE_EVENT:
            linux_trace_event_formats = tracecmd_parse_event_formats_buf(format_data, byte_swapped);

            if (linux_trace_event_formats == NULL)
                return FALSE;

            // make sure map of machine IDs to event formats is initialized,
            // and populate it with the event formats for this machine.
            if (wth->linux_trace_event_formats == NULL)
                wth->linux_trace_event_formats = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, free_event_formats_cb);
            
            pmachine_id = g_new(guint32, 1);
            *pmachine_id = machine_id;
            g_hash_table_insert(wth->linux_trace_event_formats, pmachine_id, linux_trace_event_formats);
            return TRUE;
        
        default:
            ws_debug("could not process event format data for unknown event type %u", event_type);
            return FALSE;
    }
}

void destroy_buffer_cb(gpointer pbuf)
{
    Buffer *buf = (Buffer *)pbuf;
    ws_buffer_free(buf);
    g_free(buf);
}

static gboolean traceshark_read_event_format_block(FILE_T fh, guint32 block_read, gboolean byte_swapped, wtapng_block_t *wblock, int *err, gchar **err_info)
{
    struct traceshark_event_format_block block;
    guint32 pad_size;
    Buffer *buf = NULL;
    struct traceshark_wblock_custom_data *custom_data;

    // make sure we can read a full block header
    if (sizeof(block) > block_read) {
        *err_info = g_strdup_printf("traceshark: block length %u of an EFB is less than the minimum EFB size %u",
                                        block_read, (guint32)sizeof(block));
        goto error;
    }

    // read the block header
    if (!wtap_read_bytes(fh, &block, sizeof(block), err, err_info))
        return FALSE;
    block_read -= sizeof(block);

    // fix byte order
    if (byte_swapped) {
        block.machine_id = GUINT32_SWAP_LE_BE(block.machine_id);
        block.event_type = GUINT16_SWAP_LE_BE(block.event_type);
        block.formats_size = GUINT32_SWAP_LE_BE(block.formats_size);
    }

    if (block.formats_size == 0) {
        *err_info = g_strdup_printf("traceshark: empty event format data");
        goto error;
    }

    // calculate pad size
    if ((block.formats_size % 4) != 0)
        pad_size = 4 - (block.formats_size % 4);
    else
        pad_size = 0;
    
    // make sure we can read the event format data
    if (block.formats_size + pad_size > block_read) {
        *err_info = g_strdup_printf("traceshark: remaining block length %u of an EFB is less than the formats size %u",
                                        block_read, block.formats_size + pad_size);
        goto error;
    }

    // read the event format data
    buf = g_new(Buffer, 1);
    ws_buffer_init(buf, block.formats_size);
    if (!wtap_read_packet_bytes(fh, buf, block.formats_size, err, err_info))
        goto cleanup;
    ws_buffer_increase_length(buf, block.formats_size);
    
    block_read -= block.formats_size;
    
    // skip over padding
    if (!wtap_read_bytes(fh, NULL, pad_size, err, err_info))
        goto cleanup;
    block_read -= pad_size;

    // make sure there is no remaining data
    if (block_read > 0) {
        *err_info = g_strdup_printf("traceshark: %u bytes of data remain after finished processing EFB", block_read);
        goto error;
    }

    // set up custom data and add it to wblock
    custom_data = g_new0(struct traceshark_wblock_custom_data, 1);
    custom_data->data.event_format_data.machine_id = block.machine_id;
    custom_data->data.event_format_data.event_type = block.event_type;
    custom_data->data.event_format_data.format_data = buf;
    wblock->custom_data = custom_data;

    wblock->internal = TRUE;

    return TRUE;

error:
    *err = WTAP_ERR_BAD_FILE;

cleanup:
    if (buf != NULL) {
        ws_buffer_free(buf);
        g_free(buf);
    }

    return FALSE;
}

void traceshark_write_event_format_block(gpointer key, gpointer value, gpointer user_data)
{
    pcapng_block_header_t bh;
    struct traceshark_event_format_block efb;
    guint32 pad_size;
    const guint32 zero_pad = 0;
    guint64 *pkey = (guint64 *)key;
    Buffer *buf = (Buffer *)value;
    struct dumper_cb_data *cb_data = (struct dumper_cb_data *)user_data;

    if (cb_data->failed)
        return;

    // populate format block fields
    efb.machine_id = (*pkey) >> 32;
    efb.event_type = (*pkey) & 0xffff;
    efb.formats_size = (guint32)ws_buffer_length(buf);

    ws_debug("adding event format block for machine ID %u and event type %u", efb.machine_id, efb.event_type);

    // calculate pad size
    if (efb.formats_size % 4 != 0)
        pad_size = 4 - efb.formats_size % 4;
    else
        pad_size = 0;
    
    bh.block_type = BLOCK_TYPE_EVENT_FORMAT;
    bh.block_total_length = sizeof(bh) + sizeof(efb) + efb.formats_size + pad_size + 4;

    // write block header
    if (!wtap_dump_file_write(cb_data->wdh, &bh, sizeof(bh), cb_data->err))
        goto error;
    cb_data->wdh->bytes_dumped += sizeof(bh);

    // write event format block
    if (!wtap_dump_file_write(cb_data->wdh, &efb, sizeof(efb), cb_data->err))
        goto error;
    cb_data->wdh->bytes_dumped += sizeof(efb);

    // write event format data
    if (!wtap_dump_file_write(cb_data->wdh, ws_buffer_start_ptr(buf), efb.formats_size, cb_data->err))
        goto error;
    cb_data->wdh->bytes_dumped += efb.formats_size;

    // write padding
    if (!wtap_dump_file_write(cb_data->wdh, &zero_pad, pad_size, cb_data->err))
        goto error;
    cb_data->wdh->bytes_dumped += pad_size;
    
    // write block footer
    if (!wtap_dump_file_write(cb_data->wdh, &bh.block_total_length, sizeof(bh.block_total_length), cb_data->err))
        goto error;
    cb_data->wdh->bytes_dumped += sizeof(bh.block_total_length);

    return;

error:
    cb_data->failed = TRUE;
}

void free_machine_info_data_cb(gpointer data)
{
    struct traceshark_machine_info_data *machine_info = (struct traceshark_machine_info_data *)data;

    g_free(machine_info->hostname);
    g_free(machine_info->os_version);

    g_free(machine_info);
}

static gboolean traceshark_read_machine_info_block(FILE_T fh, guint32 block_read, gboolean byte_swapped, wtapng_block_t *wblock, int *err, gchar **err_info)
{
    struct traceshark_machine_info_block block;
    struct traceshark_wblock_custom_data *custom_data;
    struct traceshark_machine_info_data *machine_info;

    // make sure we can read a full block header
    if (sizeof(block) > block_read) {
        *err_info = g_strdup_printf("traceshark: block length %u of an MIB is less than the minimum MIB size %u",
                                        block_read, (guint32)sizeof(block));
        goto error;
    }

    // read the block header
    if (!wtap_read_bytes(fh, &block, sizeof(block), err, err_info))
        return FALSE;
    block_read -= sizeof(block);

    // fix byte order
    if (byte_swapped)
        block.machine_id = GUINT32_SWAP_LE_BE(block.machine_id);
    
    // set up custom data and add it to wblock
    custom_data = g_new(struct traceshark_wblock_custom_data, 1);
    machine_info = g_new0(struct traceshark_machine_info_data, 1);
    custom_data->data.machine_info_data = machine_info;
    machine_info->machine_id = block.machine_id;
    wblock->custom_data = custom_data;
    
    // remaining block data is options
    if (block_read > 0) {
        if (!read_options(fh, &block_read, byte_swapped, wblock, 0, err, err_info))
            return FALSE;
    }

    // make sure there is no remaining data
    if (block_read > 0) {
        *err_info = g_strdup_printf("traceshark: %u bytes of data remain after finished processing MIB", block_read);
        goto error;
    }

    wblock->internal = TRUE;

    return TRUE;

error:
    *err = WTAP_ERR_BAD_FILE;
    return FALSE;
}

static guint32 compute_machine_info_block_options_size(struct traceshark_machine_info_data *machine_info)
{
    guint num_options = 0;
    guint32 options_data_size = 0;

    // hostname
    if (machine_info->hostname != NULL) {
        num_options++;
        options_data_size += strlen(machine_info->hostname) + 1;

        // pad to 32-bit boundary
        if (options_data_size % 4 != 0)
            options_data_size += 4 - (options_data_size % 4);
    }

    // OS type
    num_options++;
    options_data_size += sizeof(guint16);

    // pad to 32-bit boundary
    options_data_size += 2;

    // OS version
    if (machine_info->os_version != NULL) {
        num_options++;
        options_data_size += strlen(machine_info->os_version) + 1;

        // pad to 32-bit boundary
        if (options_data_size % 4 != 0)
            options_data_size += 4 - (options_data_size % 4);
    }

    // architecture
    num_options++;
    options_data_size += sizeof(guint16);

    // pad to 32-bit boundary
    options_data_size += 2;

    // num CPUs
    if (machine_info->num_cpus > 0) {
        num_options++;
        options_data_size += sizeof(guint32);
    }

    return sizeof(struct pcapng_option_header) * (num_options + 1) + options_data_size;
}

void traceshark_write_machine_info_block(gpointer key _U_, gpointer value, gpointer user_data)
{
    pcapng_block_header_t bh;
    struct traceshark_machine_info_block mib;
    guint32 options_size;
    struct traceshark_machine_info_data *machine_info = (struct traceshark_machine_info_data *)value;
    struct dumper_cb_data *cb_data = (struct dumper_cb_data *)user_data;

    if (cb_data->failed)
        return;
    
    mib.machine_id = machine_info->machine_id;

    ws_debug("adding machine info block for machine ID %u", mib.machine_id);

    options_size = compute_machine_info_block_options_size(machine_info);

    bh.block_type = BLOCK_TYPE_MACHINE_INFO;
    bh.block_total_length = sizeof(bh) + sizeof(mib) + options_size + 4;

    // write block header
    if (!wtap_dump_file_write(cb_data->wdh, &bh, sizeof(bh), cb_data->err))
        goto error;
    cb_data->wdh->bytes_dumped += sizeof(bh);

    // write machine info block
    if (!wtap_dump_file_write(cb_data->wdh, &mib, sizeof(mib), cb_data->err))
        goto error;
    cb_data->wdh->bytes_dumped += sizeof(mib);

    // write options
    if (!write_options(cb_data->wdh, BLOCK_TYPE_MACHINE_INFO, machine_info, cb_data->err))
        goto error;
    
    // write block footer
    if (!wtap_dump_file_write(cb_data->wdh, &bh.block_total_length, sizeof(bh.block_total_length), cb_data->err))
        goto error;
    cb_data->wdh->bytes_dumped += sizeof(bh.block_total_length);
    
    return;

error:
    cb_data->failed = TRUE;
}

/**
 * This is a stub block writer for block types that have no associtated records.
*/
static gboolean traceshark_block_writer_stub(wtap_dumper *wdh _U_, const wtap_rec *rec _U_, const guint8 *pd _U_, int *err _U_)
{
    return FALSE;
}

void register_traceshark(void)
{
    register_pcapng_block_type_handler(BLOCK_TYPE_EVENT, traceshark_read_event_block, traceshark_write_event_block);
    register_pcapng_block_type_handler(BLOCK_TYPE_EVENT_FORMAT, traceshark_read_event_format_block, traceshark_block_writer_stub);
    register_pcapng_block_type_handler(BLOCK_TYPE_MACHINE_INFO, traceshark_read_machine_info_block, traceshark_block_writer_stub);
}