#pragma once

#include <signal.h>

#include "shm.h"

int main_loop(entry_callback_t cb, const volatile sig_atomic_t *stop_loop, void *arg) _wur_;
