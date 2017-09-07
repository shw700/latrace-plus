/* /usr/include/sys/syslog.h */


enum_bm openlog_opt {
	LOG_PID    = 0x01,
	LOG_CONS   = 0x02,
	LOG_ODELAY = 0x04,
	LOG_NDELAY = 0x08,
	LOG_NOWAIT = 0x10,
	LOG_PERROR = 0x20
};

enum openlog_facility {
	LOG_KERN     = 0,
	LOG_USER     = 0x008,
	LOG_MAIL     = 0x010,
	LOG_DAEMON   = 0x018,
	LOG_AUTH     = 0x020,
	LOG_SYSLOG   = 0x028,
	LOG_LPR      = 0x030,
	LOG_NEWS     = 0x038,
	LOG_UUCP     = 0x040,
	LOG_CRON     = 0x048,
	LOG_AUTHPRIV = 0x050,
	LOG_FTP      = 0x058,
	LOG_LOCAL0   = 0x080,
	LOG_LOCAL1   = 0x088,
	LOG_LOCAL2   = 0x090,
	LOG_LOCAL3   = 0x098,
	LOG_LOCAL4   = 0x0a0,
	LOG_LOCAL5   = 0x0a8,
	LOG_LOCAL6   = 0x0b0,
	LOG_LOCAL7   = 0x0b8
};


void closelog();
void openlog~(char *ident, int option=openlog_opt, int facility=openlog_facility);
int  setlogmask(int mask);
void syslog(int pri, char *fmt);
void vsyslog(int pri, char *fmt);
