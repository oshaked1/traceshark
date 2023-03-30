#include "wtap.h"

#ifndef __TRACECMD_H__
#define __TRACECMD_H__

struct linux_trace_event_options {
    gboolean big_endian;
    guint32 cpu;
};

WS_DLL_PUBLIC int tracecmd_get_file_type_subtype(void);

wtap_open_return_val tracecmd_open(wtap *wth, int *err, gchar **err_info);

#endif /* __TRACECMD_H__ */