#include "output_sqlite.h"

#include <assert.h>
#include <stdlib.h>

#include "arpobserver.h"
#include "log.h"
#include "util.h"

#ifdef HAVE_LIBSQLITE3
static const char sqlite_create_template[] = "\
CREATE TABLE IF NOT EXISTS %s(\
timestamp UNSIGNED BIG INT, \
interface varchar(16), \
vlan_tag UNSIGNED INT, \
mac_address varchar(17), \
ip_address varchar(42), \
origin TINYINT\
);";

static const char sqlite_insert_template[] = "INSERT INTO %s VALUES(?, ?, ?, ?, ?, ?);";

static sqlite3 *sqlite_conn = NULL;
static sqlite3_stmt *sqlite_stmt;
#endif

int output_sqlite_init(void)
{
#ifdef HAVE_LIBSQLITE3
	const char *tablename = global_cfg.sqlite_tablename ?: PACKAGE;
	int rc;
	char create_query[sizeof(sqlite_create_template) + 64];
	char insert_query[sizeof(sqlite_insert_template) + 64];

	if (!global_cfg.sqlite_filename) {
		log_debug("No sqlite3 database specified. Skipping initialization...");
		return 0;
	}

	a_snprintf(create_query, sizeof(create_query), sqlite_create_template, tablename);
	a_snprintf(insert_query, sizeof(insert_query), sqlite_insert_template, tablename);

	rc = sqlite3_open(global_cfg.sqlite_filename, &sqlite_conn);
	if (rc) {
		log_error("Unable to open sqlite3 database file '%s'", global_cfg.sqlite_filename);
		return -1;
	}

	log_debug("Using sqlite3 create query: %s", create_query);
	rc = sqlite3_exec(sqlite_conn, create_query, 0, 0, 0);
	if (rc) {
		log_error("Error creating table '%s' in sqlite3 database", tablename);
		return -1;
	}

	log_debug("Using sqlite3 insert query: %s", insert_query);
	rc = sqlite3_prepare_v2(sqlite_conn, insert_query, sizeof(insert_query), &sqlite_stmt, NULL);
	if (rc) {
		log_error("Error preparing sqlite3 insert statement");
		return -1;
	}

	sqlite3_busy_timeout(sqlite_conn, 100);
	log_debug("Saving results to sqlite3 database '%s'", global_cfg.sqlite_filename);
#endif
	return 0;
}

int output_sqlite_reload(void)
{
	output_sqlite_close();

	return output_sqlite_init();
}

int output_sqlite_save(const struct pkt *p, const char *mac_str, const char *ip_str)
{
#ifdef HAVE_LIBSQLITE3
	int rc;

	assert(p);
	assert(mac_str);
	assert(ip_str);

	if (!sqlite_conn) {
		log_debug("No sqlite3 database specified. Skipping save...");
		return 0;
	}

	rc = sqlite3_bind_int64(sqlite_stmt, 1, p->pcap_header->ts.tv_sec);
	rc += sqlite3_bind_text(sqlite_stmt, 2, p->ifc->name, -1, NULL);
	rc += sqlite3_bind_int(sqlite_stmt, 3, p->vlan_tag);
	rc += sqlite3_bind_text(sqlite_stmt, 4, mac_str, -1, NULL);
	rc += sqlite3_bind_text(sqlite_stmt, 5, ip_str, -1, NULL);
	rc += sqlite3_bind_int(sqlite_stmt, 6, (int)p->origin);
	if (rc) {
		log_error("Unable to bind values to sql statement");
		sqlite3_reset(sqlite_stmt);
		return -1;
	}

	rc = sqlite3_step(sqlite_stmt);
	switch (rc) {
	case SQLITE_DONE:
		break;
	case SQLITE_BUSY:
		log_warn("Unable to execute sqlite prepared statement, database is locked (%ld, %s, %s, %s)", p->pcap_header->ts.tv_sec,
			 p->ifc->name, mac_str, ip_str);
		break;
	default:
		log_error("Error executing sqlite prepared statement (%d)", rc);
		sqlite3_reset(sqlite_stmt);
		return -1;
	}

	rc = sqlite3_reset(sqlite_stmt);
	if (rc && rc != SQLITE_BUSY) {
		log_error("Error resetting sqlite prepared statement (%d)", rc);
		return -1;
	}
#endif
	return 0;
}

void output_sqlite_close(void)
{
#ifdef HAVE_LIBSQLITE3
	if (sqlite_conn) {
		sqlite3_finalize(sqlite_stmt);
		sqlite3_close(sqlite_conn);
	}
#endif
}
