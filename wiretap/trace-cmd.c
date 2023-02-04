#include "wtap-int.h"
#include "file_wrappers.h"

static const unsigned char tracecmd_magic[3] = { 0x17, 0x08, 0x44 };

static int tracecmd_file_type_subtype = -1;

static gboolean tracecmd_read(wtap* wth, wtap_rec* rec, Buffer* buf,
	int* err, gchar** err_info, gint64* data_offset)
{
	return FALSE;
}

/* Used to read packets in random-access fashion */
static gboolean tracecmd_seek_read(wtap* wth, gint64 seek_off,
	wtap_rec* rec, Buffer* buf, int* err, gchar** err_info)
{
	return FALSE;
}

wtap_open_return_val tracecmd_open(wtap *wth, int *err, gchar **err_info _U_)
{
	unsigned char buf[3];

	if (file_read(&buf, sizeof(buf), wth->fh) == 0) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	if (memcmp(&buf, tracecmd_magic, 3) != 0)
		return WTAP_OPEN_NOT_MINE;
	
	ws_debug("trace-cmd magic found");
	
	wth->file_type_subtype = tracecmd_file_type_subtype;
	wth->subtype_read = tracecmd_read;
	wth->subtype_seek_read = tracecmd_seek_read;
	
	return WTAP_OPEN_MINE;
}

static const struct supported_block_type tracecmd_blocks_supported[] = {
	/*
	 * We support packet blocks, with no comments or other options.
	 */
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