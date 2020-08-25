#include <assert.h>
#include <getopt.h>
#include <mysql/mysql.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "daemonize.h"
#include "log.h"
#include "shm.h"
#include "shm_client.h"

#define MYSQL_ARGV0  "arpobserver-mysql"
#define HOSTNAME_LEN 255


struct ctx_s {
	const char *config_file;
	const char *prefix;
	MYSQL *dbh;
	MYSQL_STMT *stmt;
	MYSQL_BIND bind[7];
	struct {
		long long int timestamp;
		char hostname[HOSTNAME_LEN];
		unsigned long hostname_len;
		char iface[IFNAMSIZ];
		unsigned long iface_len;
		int vlan_tag;
		char mac[ETHER_ADDR_LEN];
		unsigned long mac_len;
		char ip[IP6_LEN];
		unsigned long ip_len;
		int origin;
	} bind_data;
};

static const char *const sql_create_log_template = "\
CREATE TABLE IF NOT EXISTS `%slog` (\
	`tstamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,\
	`hostname` varchar(" STR(HOSTNAME_LEN) ") NOT NULL DEFAULT \"localhost\",\
	`interface` varchar(16) NOT NULL,\
	`vlan_tag` int(11) NOT NULL DEFAULT 0,\
	`mac_address` BINARY(6) NOT NULL,\
	`ip_address` VARBINARY(16) NOT NULL,\
	`origin_id` INT(11) NOT NULL,\
\
	KEY `interface` (`interface`),\
	KEY `vlan_tag` (`vlan_tag`),\
	KEY `mac_address` (`mac_address`),\
	KEY `interface_vlan_tag` (`interface`,`vlan_tag`)\
)";

static const char *const sql_create_origin_template = "\
CREATE TABLE IF NOT EXISTS `%sorigin` (\
	`id` INT(11) NOT NULL,\
	`name` VARCHAR(16) NOT NULL,\
	`description` VARCHAR(255) NOT NULL,\
\
	PRIMARY KEY (`id`)\
)";

static const char *const sql_create_plaintext_template = "\
CREATE OR REPLACE VIEW `%slog_plaintext` AS \
SELECT \
	l.`tstamp`, \
	l.`hostname`, \
	l.`interface`, \
	l.`vlan_tag`, \
	HEX(l.`mac_address`) AS `mac_address`, \
	HEX(l.`ip_address`) AS `ip_address`, \
	o.`name` AS `origin` \
FROM `%slog` AS l \
INNER JOIN `%sorigin` as o \
	ON o.`id` = l.`origin_id`";

static const char *const sql_insert_log_template = "\
INSERT INTO `%slog` (\
	`tstamp`, `hostname`, `interface`, `vlan_tag`, `mac_address`, `ip_address`, `origin_id`\
) \
VALUES(\
	FROM_UNIXTIME(?), ?, ?, ?, ?, ?, ?\
)";

static const char *const sql_insert_origin_template = "\
INSERT INTO `%sorigin` (\
	`id`, `name`, `description`\
) \
VALUES(\
	%u, '%s', '%s'\
)";


__attribute__((format(printf, 2, 3))) static int mysql_simple_query(MYSQL *dbh, const char *format, ...)
{
	va_list pvar;
	char buf[BUFSIZ];

	assert(dbh);
	assert(format);

	va_start(pvar, format);
	vsnprintf(buf, sizeof(buf), format, pvar);
	va_end(pvar);

	if (mysql_query(dbh, buf)) {
		log_error("Error executing query: %s", mysql_error(dbh));
		return -1;
	}

	return 0;
}

static int mysql_init_tables(MYSQL *dbh, const char *prefix)
{
	int r;

	assert(dbh);

	r = mysql_simple_query(dbh, sql_create_log_template, prefix);
	if (r < 0)
		return r;

	r = mysql_simple_query(dbh, sql_create_origin_template, prefix);
	if (r < 0)
		return r;

	if (!mysql_warning_count(dbh)) {
		for (int i = 0; pkt_origin_str[i]; i++) {
			r = mysql_simple_query(dbh, sql_insert_origin_template, prefix, i, pkt_origin_str[i], pkt_origin_desc[i]);
			if (r < 0)
				return r;
		}
	}

	return mysql_simple_query(dbh, sql_create_plaintext_template, prefix, prefix, prefix);
}

static int stmt_init(struct ctx_s *data)
{
	int r;
	size_t len;
	char *buf;

	assert(data);

	data->stmt = mysql_stmt_init(data->dbh);
	if (!data->stmt) {
		log_error("Error allocating MySQL statement object");
		return -1;
	}

	len = strlen(sql_insert_log_template) + strlen(data->prefix) + 1;
	buf = malloc(len);
	if (!buf)
		return log_oom();

	snprintf(buf, len, sql_insert_log_template, data->prefix);

	r = mysql_stmt_prepare(data->stmt, buf, strnlen(buf, len));
	if (r) {
		free(buf);
		log_error("Error preparing MySQL statement object: %s", mysql_stmt_error(data->stmt));
		return -1;
	}
	free(buf);

	if (mysql_stmt_bind_param(data->stmt, data->bind)) {
		log_error("Error binding MySQL statement object: %s", mysql_stmt_error(data->stmt));
		return -1;
	}

	return 0;
}

static int db_connect(struct ctx_s *data)
{
	int r;

	assert(data);

	data->dbh = mysql_init(data->dbh);
	if (!data->dbh) {
		log_error("Error allocating MySQL object");
		return -1;
	}

	if (data->config_file) {
		r = mysql_options(data->dbh, MYSQL_READ_DEFAULT_FILE, data->config_file);
		if (r) {
			log_error("Failed to read config file %s: %s", data->config_file, mysql_error(data->dbh));
			return -1;
		}
	}

	r = mysql_options(data->dbh, MYSQL_READ_DEFAULT_GROUP, PACKAGE);
	if (r) {
		log_error("Failed to read [" PACKAGE "] section from my.cnf: %s", mysql_error(data->dbh));
		return -1;
	}

	if (!mysql_real_connect(data->dbh, NULL, NULL, NULL, NULL, 0, NULL, 0)) {
		log_warn("Failed to connect to database: %s", mysql_error(data->dbh));
		return -1;
	}

	r = mysql_init_tables(data->dbh, data->prefix);
	if (r < 0)
		return r;

	return stmt_init(data);
}

static void db_disconnect(struct ctx_s *data)
{
	assert(data);

	if (data->stmt) {
		mysql_stmt_close(data->stmt);
		data->stmt = NULL;
	}
	mysql_close(data->dbh);
	data->dbh = NULL;
}

static void db_reconnect(struct ctx_s *data)
{
	assert(data);

	for (;;) {
		if (data->dbh) {
			db_disconnect(data);
		}
		if (!db_connect(data)) {   // TODO
			break;
		}
		sleep(1);
	}
}

static void bind_init(struct ctx_s *data)
{
	assert(data);

	memset(data->bind, 0, sizeof(data->bind));

	data->bind[0].buffer_type = MYSQL_TYPE_LONGLONG;
	data->bind[0].buffer = &data->bind_data.timestamp;

	data->bind[1].buffer_type = MYSQL_TYPE_STRING;
	data->bind[1].buffer = &data->bind_data.hostname;
	data->bind[1].length = &data->bind_data.hostname_len;

	data->bind[2].buffer_type = MYSQL_TYPE_STRING;
	data->bind[2].buffer = &data->bind_data.iface;
	data->bind[2].length = &data->bind_data.iface_len;

	data->bind[3].buffer_type = MYSQL_TYPE_LONG;
	data->bind[3].buffer = &data->bind_data.vlan_tag;

	data->bind[4].buffer_type = MYSQL_TYPE_BLOB;
	data->bind[4].buffer = &data->bind_data.mac;
	data->bind[4].length = &data->bind_data.mac_len;

	data->bind[5].buffer_type = MYSQL_TYPE_BLOB;
	data->bind[5].buffer = &data->bind_data.ip;
	data->bind[5].length = &data->bind_data.ip_len;

	data->bind[6].buffer_type = MYSQL_TYPE_LONG;
	data->bind[6].buffer = &data->bind_data.origin;
}

static void process_entry(const struct shm_log_entry *e, void *arg)
{
	struct ctx_s *data = arg;

	assert(e);
	assert(data);

	data->bind_data.timestamp = e->timestamp;
	memcpy(data->bind_data.iface, e->interface, sizeof(data->bind_data.iface));
	data->bind_data.iface_len = strnlen(data->bind_data.iface, sizeof(data->bind_data.iface));
	data->bind_data.vlan_tag = e->vlan_tag;
	memcpy(data->bind_data.mac, e->mac_address, sizeof(e->mac_address));
	data->bind_data.mac_len = sizeof(data->bind_data.mac);
	memcpy(data->bind_data.ip, e->ip_address, e->ip_len);
	data->bind_data.ip_len = e->ip_len;
	data->bind_data.origin = e->origin;

	for (;;) {
		if (!mysql_stmt_execute(data->stmt)) {
			return;
		}
		log_warn("Error inserting data to MySQL database: %s\n", mysql_stmt_error(data->stmt));

		db_reconnect(data);
	}
}

static int get_hostname(char *hostname, size_t *len)
{
	if (gethostname(hostname, *len))
		return log_error("Error gethostbyname failed: %m");

	*len = strnlen(hostname, *len);
	return 0;
}

static void usage(void)
{
	printf("Usage: " MYSQL_ARGV0 " [OPTIONS]\n"
	       "Save address events in a MySQL database.\n\n"
	       "  -c, --config=FILE\t\tUse FILE for MySQL configuration.\n"
	       "  -f, --foreground\t\tStart as a foreground process.\n"
	       "  -h, --help\t\t\tDisplay this menu.\n"
	       "  -p, --prefix=STR\t\tPrepend STR as prefix to table names.\n"
	       "  -v, --verbose\t\t\tEnable verbose output.\n"
	       "  -V, --version\t\t\tShow version information and exit.\n");
}

int main(int argc, char *argv[])
{
	int r;
	bool foreground = false;
	bool verbose = false;
	struct ctx_s ctx;

	const struct option long_options[] = {
		{"config", required_argument, NULL, 'c'},
		{"foreground", no_argument, NULL, 'f'},
		{"help", no_argument, NULL, 'h'},
		{"prefix", required_argument, NULL, 'p'},
		{"verbose", no_argument, NULL, 'v'},
		{"version", no_argument, NULL, 'V'},
		{0, 0, 0, 0},
	};

	memset(&ctx, 0, sizeof(ctx));
	ctx.prefix = "";

	for (;;) {
		int option_index = 0;

		int c = getopt_long(argc, argv, "c:fhp:vV", long_options, &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
		case 0:
			break;

		case 'c':
			ctx.config_file = optarg;
			break;

		case 'f':
			foreground = true;
			break;

		case 'h':
			usage();
			exit(EXIT_SUCCESS);

		case 'p':
			ctx.prefix = optarg;
			break;

		case 'v':
			verbose = true;
			break;

		case 'V':
			printf("%s %s\n", MYSQL_ARGV0, VERSION);
			exit(EXIT_SUCCESS);

		case '?':
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}

	log_open(MYSQL_ARGV0);
	if (verbose)
		log_max_priority(LOG_DEBUG);

	ctx.bind_data.hostname_len = sizeof(ctx.bind_data.hostname);
	r = get_hostname(ctx.bind_data.hostname, &ctx.bind_data.hostname_len);
	if (r < 0)
		return EXIT_FAILURE;

	r = mysql_library_init(0, NULL, NULL);
	if (r) {
		log_error("Error initializing MySQL library (%d)", r);
		return EXIT_FAILURE;
	}

	bind_init(&ctx);
	db_reconnect(&ctx);

	if (!foreground) {
		log_mode(LOG_MODE_SYSLOG);

		if (daemonize(NULL) < 0)
			return EXIT_FAILURE;
	}

	r = main_loop(process_entry, NULL, &ctx);

	mysql_library_end();

	log_close();

	return r ? EXIT_FAILURE : EXIT_SUCCESS;
}
