#include "statefile.h"

#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "cleanup.h"
#include "common.h"
#include "log.h"
#include "macro.h"
#include "shm.h"
#include "util.h"

int lock_state_file(const char *path)
{
	_cleanup_close_ int fd = -1;

	assert(path);

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		if (errno != ENOENT)
			return log_error("Cannot open state file '%s': %m", path);

		fd = open(path, O_RDWR | O_CLOEXEC | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP);
		if (fd < 0)
			return log_error("Cannot create state file '%s': %m", path);
	}

	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		if (errno == EWOULDBLOCK)
			return log_error("Cannot lock state file '%s', already locked.", path);

		return log_error("Cannot lock state file '%s': %m", path);
	}

	return TAKE_FD(fd);
}

_access_rwc_(1, 2) _nonnull_ static int parse_state_line(char *line, size_t len, struct dllist_head *state)
{
	time_t timestamp;
	char interface[IFNAMSIZ];
	char mac_str[MAC_STR_LEN];
	char ip_str[INET6_ADDRSTRLEN];
	_cleanup_shmlogentry_ struct shm_log_entry *new_data = NULL;
	const char *line_p = line, *comma;
	char *endptr;
	long unsigned int strtoul_result;
	size_t remaining_len;

	for (size_t line_len = len; line_len > 0 && line[line_len - 1] == '\n'; line_len--) {
		line[line_len - 1] = '\0';
	}

	comma = strchr(line_p, ',');
	if (!comma) {
		log_warn("Cannot parse state entry '%s' (1), ignoring entry..", line);
		return 0;
	}

	strtoul_result = strtoul(line_p, &endptr, 10);
	timestamp = (time_t)strtoul_result;
	if (strtoul_result == ULONG_MAX || timestamp < 0 || endptr != comma) {
		log_warn("Cannot parse timestamp of state entry '%s', ignoring entry..", line);
		return 0;
	}

	line_p = comma + 1;

	comma = strchr(line_p, ',');
	if (!comma || (size_t)(comma - line_p) >= sizeof(interface)) {
		log_warn("Cannot parse state entry '%s' (2), ignoring entry..", line);
		return 0;
	}

	safe_strncpy(interface, line_p, (size_t)(comma - line_p));

	line_p = comma + 1;

	comma = strchr(line_p, ',');
	if (!comma || (size_t)(comma - line_p) >= sizeof(mac_str)) {
		log_warn("Cannot parse state entry '%s' (3), ignoring entry..", line);
		return 0;
	}

	safe_strncpy(mac_str, line_p, (size_t)(comma - line_p));

	line_p = comma + 1;

	if (strchr(line_p, ',')) {
		log_warn("Cannot parse state entry '%s' (4), ignoring entry..", line);
		return 0;
	}

	remaining_len = strlen(line_p);
	if (remaining_len == 0 || remaining_len >= sizeof(ip_str)) {
		log_warn("Cannot parse state entry '%s' (5), ignoring entry..", line);
		return 0;
	}

	safe_strncpy(ip_str, line_p, remaining_len);

	new_data = calloc(1, sizeof(struct shm_log_entry));
	if (!new_data)
		return log_oom();

	new_data->timestamp = timestamp;
	safe_strncpy(new_data->interface, interface, sizeof(new_data->interface));

	if (convert_mac_str_to_addr(mac_str, new_data->mac_address) < 0) {
		log_warn("%s: Cannot convert MAC address '%s' to binary form: %m", __func__, mac_str);
		return 0;
	}

	if (strchr(ip_str, '.') != NULL) {
		new_data->ip_len = IP4_LEN;
		if (convert_ip4_str_to_addr(ip_str, &new_data->ip_address) < 0) {
			log_warn("%s: Cannot convert IPv4 address '%s' to binary form: %m", __func__, ip_str);
			return 0;
		}
	} else if (strchr(ip_str, ':') != NULL) {
		new_data->ip_len = IP6_LEN;
		if (convert_ip6_str_to_addr(ip_str, &new_data->ip_address) < 0) {
			log_warn("%s: Cannot convert IPv6 address '%s' to binary form: %m", __func__, ip_str);
			return 0;
		}
	} else {
		log_warn("Cannot parse ip address '%s' of state entry '%s', ignoring entry..", ip_str, line);
		return 0;
	}

	/*if (verbose) {
		char mac_str_test[MAC_STR_LEN];
		char ip_str_test[INET6_ADDRSTRLEN];
		convert_mac_addr_to_str(new_data->mac_address, mac_str_test);

		if (convert_ip_addr_to_str(new_data->ip_address, new_data->ip_len, ip_str_test) < 0)
			snprintf(ip_str_test, sizeof(ip_str_test), CONVERSION_FAILURE_STR);

		log_debug("Converted state line '%s' into %lu,%s,%s,%s", line, new_data->timestamp, interface, mac_str_test, ip_str_test);
	}*/

	if (dllist_push_back(state, TAKE_PTR(new_data)) < 0)
		return log_oom();

	return 0;
}

int read_state_file(const char *path, struct dllist_head *state)
{
	_cleanup_fclose_ FILE *stream = NULL;
	_cleanup_free_ char *line = NULL;
	size_t len = 0;
	ssize_t read;

	assert(path);
	assert(state);

	log_debug("Reading state from disk...");

	stream = fopen(path, "re");
	if (!stream)
		return log_error("Cannot open state file '%s': %m", path);

	while ((read = getline(&line, &len, stream)) != -1) {
		int r = parse_state_line(line, (size_t)read, state);
		if (r < 0)
			return r;
	}

	log_info("Loaded %zu state entries from disk.", state->size);
	return 0;
}

void dump_state(const struct dllist_head *state)
{
	time_t current;
	char current_time_str[32];
	struct tm timeresult;

	assert(state);

	if (state->size == 0)
		printf("<<empty>>");
	else {
		printf("  %32s  %16s  %18s  %s\n", "Time", "Interface", "MAC address", "IP address");

		for (const struct dllist_entry *e = state->first; e; e = e->next) {
			char last_updated[32];
			char mac_str[MAC_STR_LEN];
			char ip_str[INET6_ADDRSTRLEN];
			const struct shm_log_entry *data = e->data;

			assert(data);

			convert_mac_addr_to_str(data->mac_address, mac_str);

			if (convert_ip_addr_to_str(data->ip_address, data->ip_len, ip_str) < 0)
				snprintf(ip_str, sizeof(ip_str), CONVERSION_FAILURE_STR);

			strftime(last_updated, sizeof(last_updated), "%Y-%m-%d %H:%M:%S %z", localtime_r(&data->timestamp, &timeresult));

			printf("  %32s  %16s  %18s  %s\n", last_updated, data->interface, mac_str, ip_str);
		}
	}

	current = time(NULL);
	strftime(current_time_str, sizeof(current_time_str), "%Y-%m-%d %H:%M:%S %z", localtime_r(&current, &timeresult));
	printf("\nCurrent time:            %s\n", current_time_str);
}

int write_state_file(const char *path, const struct dllist_head *state)
{
	_cleanup_fclose_ FILE *stream = NULL;
	size_t count = 0;

	assert(path);
	assert(state);

	log_debug("Saving state to disk...");

	stream = fopen(path, "we");
	if (!stream)
		return log_error("Cannot open state file '%s': %m", path);

	for (const struct dllist_entry *le = state->first; le; le = le->next) {
		char mac_str[MAC_STR_LEN];
		char ip_str[INET6_ADDRSTRLEN];
		const struct shm_log_entry *data = le->data;

		assert(data);

		convert_mac_addr_to_str(data->mac_address, mac_str);

		if (convert_ip_addr_to_str(data->ip_address, data->ip_len, ip_str) < 0) {
			log_warn("%s: Cannot convert IP address to textual form: %m", __func__);
			continue;
		}

		fprintf(stream, "%lu,%s,%s,%s\n", data->timestamp, data->interface, mac_str, ip_str);
		count++;
	}

	log_debug("Saved %zu state entries to disk.", count);
	return 0;
}
