#define PREFIX "/usr"
#define LIBDIR PREFIX"/lib"
#define SYSCONFDIR "/etc"
#define SYSCONFBASENAME "norelaysmtpd.conf"
#define DATADIR "/var/spool/norelaysmtpd"

#if SQLITE
#include <sqlite3.h>
#endif

int always_refuse = 0;
int auto_mkmaildir = 0;
int do_catchall = 0;

#define CATCHALL_LOCALPART "catchall"
