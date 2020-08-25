#include "shm_client.h"

#include <assert.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cleanup.h"
#include "log.h"

static void close_log(struct shm_log **log, size_t mem_size)
{
	int r;

	assert(log);
	assert(*log);

	r = munmap(*log, mem_size);
	if (r < 0)
		log_error("Error unmapping shared memory: %m");
}

static int open_log(size_t *mem_size, struct shm_log **log, unsigned timeout)
{
	_cleanup_close_ int fd = -1;
	struct stat info;
	struct shm_log *addr;

	assert(mem_size);
	assert(log);

	for (;;) {
		fd = shm_open(DEFAULT_SHM_LOG_NAME, O_RDONLY, S_IRUSR | S_IWUSR);
		if (fd < 0) {
			if (errno != ENOENT || timeout == 0)
				return log_error("Cannot open shared memory object '%s': %m", DEFAULT_SHM_LOG_NAME);

			sleep(1);
			timeout--;
			continue;
		}
		break;
	}

	if (fstat(fd, &info) < 0)
		return log_error("Cannot stat shared memory object '%s': %m", DEFAULT_SHM_LOG_NAME);

	*mem_size = (size_t)info.st_size;
	addr = mmap(NULL, *mem_size, PROT_READ, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED)
		return log_error("Cannot map shared memory object: %m");

	if (close(TAKE_FD(fd)) < 0) {
		(void)munmap(addr, *mem_size);
		return log_error("Cannot close shared memory object '%s': %m", DEFAULT_SHM_LOG_NAME);
	}

	*log = TAKE_PTR(addr);

	return 0;
}

static int wait_for_active_log(const struct shm_log *log)
{
	int timeout = (2 * TIMEOUT_SEC + 1) / WAIT_INTERVAL_SEC;

	while (log->magic != MAGIC && !log->active && timeout-- > 0)
		sleep(WAIT_INTERVAL_SEC);

	return timeout > 0 ? 0 : -EAGAIN;
}

int main_loop(entry_callback_t cb, const volatile sig_atomic_t *stop_loop, void *arg)
{
	int r;
	size_t mem_size;
	uint64_t idx;
	struct shm_log *log;
	time_t last_event = time(NULL), last_notified = 0;
	const struct timespec poll_timespec = {.tv_sec = POLL_INTERVAL_MSEC / 1000000000,
					       .tv_nsec = (POLL_INTERVAL_MSEC * 1000 * 1000) % 1000000000};

	r = open_log(&mem_size, &log, 5);
	if (r < 0)
		return r;

	r = wait_for_active_log(log);
	if (r < 0) {
		close_log(&log, mem_size);
		return log_error("Shared memory object did not get active.");
	}

	idx = log->last_idx;

	while (stop_loop == NULL || !*stop_loop) {
		if (log->magic != MAGIC) {
			close_log(&log, mem_size);
			return -1;
		}

		if (!log->active) {
			log_info("Trying to re-open shared memory object..");
			close_log(&log, mem_size);
			r = open_log(&mem_size, &log, 5);
			if (r < 0)
				return r;

			r = wait_for_active_log(log);
			if (r < 0) {
				close_log(&log, mem_size);
				return log_error("Shared memory object did not get active.");
			}

			log_info("Shared memory object re-opened.");

			idx = log->last_idx;
			continue;
		}

		if (idx == log->last_idx) {
			time_t now = time(NULL);
			time_t time_passed = now - last_event;
			if (time_passed > 2 * TIMEOUT_SEC + 2 && now - last_notified > 5 * 60) {
				last_notified = time(NULL);
				log_warn("No event received for %ld seconds, timeout is %u.", time_passed, TIMEOUT_SEC);
			}

			nanosleep(&poll_timespec, NULL);
			continue;
		}

		idx = (idx + 1) % log->size;

		if (log->data[idx].ip_len == (uint8_t)-1) {
			last_event = time(NULL);
			continue;
		}

		cb(&log->data[idx], arg);
	}

	close_log(&log, mem_size);

	return 0;
}
