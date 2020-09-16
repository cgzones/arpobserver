bin_PROGRAMS = arpobserverd arpobserver-checkd arpobserver-dumpstate arpobserver-stdout arpobserver-syslog
if MYSQL
bin_PROGRAMS += arpobserver-mysql
endif

common_sources = arpobserver.h				\
		 cleanup.h				\
		 common.c				\
		 common.h				\
		 log.c					\
		 log.h					\
		 macro.h				\
		 shm.h					\
		 util.c					\
		 util.h

arpobserverd_SOURCES = arpobserverd.c			\
		       base64.c				\
		       base64.h				\
		       check_packet.c			\
		       check_packet.h			\
		       configfile.c			\
		       configfile.h			\
		       daemonize.c			\
		       daemonize.h			\
		       mcache.c				\
		       mcache.h				\
		       output_flatfile.c		\
		       output_flatfile.h		\
		       output_shm.c			\
		       output_shm.h			\
		       output_sqlite.c			\
		       output_sqlite.h			\
		       parse.c				\
		       parse.h				\
		       process.c			\
		       process.h			\
		       storage.c			\
		       storage.h			\
		       ${common_sources}

arpobserver_checkd_SOURCES = arpobserver-checkd.c	\
			     configfile.c		\
			     configfile.h		\
			     dllist.c			\
			     dllist.h			\
			     protect.c			\
			     protect.h			\
			     shm_client.c		\
			     shm_client.h		\
			     statefile.c		\
			     statefile.h		\
			     ${common_sources}

arpobserver_dumpstate_SOURCES = arpobserver-dumpstate.c	\
				dllist.c		\
				dllist.h		\
				statefile.c		\
				statefile.h		\
				${common_sources}

arpobserver_stdout_SOURCES = arpobserver-stdout.c	\
			     shm_client.c		\
			     shm_client.h		\
			     ${common_sources}

arpobserver_syslog_SOURCES = arpobserver-syslog.c	\
			     shm_client.c		\
			     shm_client.h		\
			     ${common_sources}

arpobserver_mysql_SOURCES = arpobserver-mysql.c		\
			    daemonize.c			\
			    daemonize.h			\
			    shm_client.c		\
			    shm_client.h		\
			    ${common_sources}

AM_CFLAGS += -DSYSCONFDIR='"$(sysconfdir)"' -DLOCALSTATEDIR='"$(localstatedir)"'

arpobserverd_LDADD = @LIBEVENT_LIBS@
