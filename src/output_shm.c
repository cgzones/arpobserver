#include "output_shm.h"

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "arpobserver.h"
#include "log.h"
#include "shm.h"

int output_shm_init()
{
	_cleanup_close_ int fd = -1;
	const size_t mem_size = sizeof(struct shm_log) + sizeof(struct shm_log_entry) * global_cfg.shm_data.size;
	void *addr;

	fd = shm_open(global_cfg.shm_data.name, O_CREAT | O_EXCL | O_CLOEXEC | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP);
	if (fd < 0)
		return log_error("Error creating shared memory object '%s': %m", global_cfg.shm_data.name);

	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		if (errno == EWOULDBLOCK) {
			return log_error("Cannot lock shared memory object '%s', already locked.", global_cfg.shm_data.name);
		}

		return log_error("Cannot lock shared memory object '%s': %m", global_cfg.shm_data.name);
	}

	if (ftruncate(fd, (off_t)mem_size) < 0) {
		return log_error("Error setting shared memory size: %m");
	}

	addr = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		return log_error("Error mapping shared memory: %m");
	}

	global_cfg.shm_data.log = TAKE_PTR(addr);

	return 0;
}

int output_shm_reload()
{
	return 0;
}

int output_shm_save(const struct pkt *p, const char *mac_str, const char *ip_str)
{
	struct shm_log *log;
	struct shm_log_entry *e;
	uint64_t idx;

	assert(p);
	assert(mac_str);
	assert(ip_str);

	log = global_cfg.shm_data.log;
	if (log->magic != MAGIC)
		idx = 0;
	else
		idx = (log->last_idx + 1) % global_cfg.shm_data.size;

	e = &log->data[idx];

	e->timestamp = p->pcap_header->ts.tv_sec;
	strncpy(e->interface, p->ifc->name, IFNAMSIZ);
	memcpy(e->ip_address, p->ip_addr, p->ip_len);
	memcpy(e->mac_address, p->l2_addr, sizeof(e->mac_address));
	e->ip_len = p->ip_len;
	e->origin = (uint8_t)p->origin;
	e->vlan_tag = p->vlan_tag;

	log->last_idx = idx;
	log->size = global_cfg.shm_data.size;
	if (log->magic != MAGIC)
		log->magic = MAGIC;
	if (!log->active)
		log->active = 1;

	return 0;
}

int output_shm_timeout()
{
	struct shm_log *log;
	struct shm_log_entry *e;
	uint64_t idx;

	log = global_cfg.shm_data.log;
	if (log->magic != MAGIC)
		idx = 0;
	else
		idx = (log->last_idx + 1) % global_cfg.shm_data.size;

	e = &log->data[idx];
	memset(e, 0, sizeof(struct shm_log_entry));
	e->ip_len = (uint8_t)-1;

	log->last_idx = idx;
	log->size = global_cfg.shm_data.size;
	if (log->magic != MAGIC)
		log->magic = MAGIC;
	if (!log->active)
		log->active = 1;

	return 0;
}

void output_shm_close()
{
	const size_t mem_size = sizeof(struct shm_log) + sizeof(struct shm_log_entry) * global_cfg.shm_data.size;
	int r;

	global_cfg.shm_data.log->active = 0;
	r = msync(global_cfg.shm_data.log, mem_size, MS_SYNC | MS_INVALIDATE);
	if (r < 0)
		log_error("Error syncing shared memory: %m");

	r = munmap(global_cfg.shm_data.log, mem_size);
	if (r < 0)
		log_error("Error unmapping shared memory: %m");

	r = shm_unlink(global_cfg.shm_data.name);
	if (r < 0)
		log_warn("Error removing shared memory object '%s': %m", global_cfg.shm_data.name);
}
