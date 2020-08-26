#pragma once

typedef int (*config_accept_func)(const char *key, const char *value);

int parse_config_file(const char *path, config_accept_func func);
