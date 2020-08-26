#include "configfile.h"

#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <string.h>

#include "cleanup.h"
#include "log.h"

static char *trim_right(char *str)
{
	size_t len = strlen(str);
	while (len > 0 && isspace((unsigned char)str[len - 1])) {
		str[len - 1] = '\0';
		--len;
	}

	return str;
}

int parse_config_file(const char *path, config_accept_func func)
{
	_cleanup_fclose_ FILE *stream = NULL;
	_cleanup_free_ char *line = NULL;
	size_t len = 0;
	ssize_t read;

	assert(path);

	stream = fopen(path, "re");
	if (!stream)
		return log_error("Cannot open configuration file '%s': %m", path);

	while ((read = getline(&line, &len, stream)) != -1) {
		const char *iter, *key_begin, *key_end, *value_begin, *value_end;
		_cleanup_free_ char *key = NULL, *value = NULL;
		char quote = 0;
		int r;

		trim_right(line);

		/* skip leading spaces */
		for (iter = line; isspace((unsigned char)*iter); ++iter) {}

		/* skip comment or empty lines */
		if (*iter == '\0' || *iter == '#')
			continue;

		key_begin = iter;

		for (; isalnum((unsigned char)*iter); ++iter) {}

		key_end = iter;

		if (key_begin >= key_end || (!isspace((unsigned char)*iter) && *iter != '='))
			return log_error("Invalid formatted key found in configuration line '%s' (0x%.2x)", line, *iter);

		/* skip whitespaces between key and '=' */
		for (; isspace((unsigned char)*iter); ++iter) {}

		if (*iter != '=')
			return log_error("No assignment found in configuration line '%s' (0x%.2x)", line, *iter);

		++iter;

		/* skip whitespaces between '=' and key */
		for (; isspace((unsigned char)*iter); ++iter) {}

		if (*iter == '\'' || *iter == '"') {
			quote = *iter;
			++iter;
		}

		value_begin = iter;

		for (; isalnum((unsigned char)*iter) || (*iter != quote && ispunct((unsigned char)*iter))
		       || (quote != 0 && isblank((unsigned char)*iter));
		     ++iter) {}

		value_end = iter;

		/* allow empty values */
		if (value_begin > value_end || (quote != 0 && quote != *iter))
			return log_error("Invalid formatted value found in configuration line '%s' (0x%.2x)", line, *iter);

		if (quote != 0)
			++iter;

		/* skip trailing spaces */
		for (; isspace((unsigned char)*iter); ++iter) {}

		if (*iter != '\0' && *iter != '#')
			return log_error("Leftover content in configuration line '%s' (0x%.2x)", line, *iter);

		key = strndup(key_begin, (size_t)(key_end - key_begin));
		value = strndup(value_begin, (size_t)(value_end - value_begin));
		if (!key || !value)
			return log_oom();

		r = func(key, value);
		if (r < 0)
			return r;
	}

	return 0;
}
