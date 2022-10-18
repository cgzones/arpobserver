#include "output_flatfile.h"

#include <assert.h>
#include <stdio.h>

#include "arpobserver.h"
#include "log.h"

static FILE *data_fd = NULL;

int output_flatfile_init(void)
{
	if (!global_cfg.data_file) {
		log_debug("No flatfile specified. Skipping initialization...");
		return 0;
	}

	data_fd = fopen(global_cfg.data_file, "ae");
	if (!data_fd)
		return log_error("Unable to open flat file '%s': %m", global_cfg.data_file);


	log_debug("Saving results to '%s' flat file", global_cfg.data_file);
	return 0;
}

int output_flatfile_reload(void)
{
	output_flatfile_close();

	return output_flatfile_init();
}

int output_flatfile_save(const struct pkt *p, const char *mac_str, const char *ip_str)
{
	assert(p);
	assert(mac_str);
	assert(ip_str);

	if (!global_cfg.data_file)
		return 0;

	assert(data_fd);

	fprintf(data_fd, "%lu %s %u %s %s %s\n", p->pcap_header->ts.tv_sec, p->ifc->name, p->vlan_tag, mac_str, ip_str,
		pkt_origin_str[p->origin]);
	fflush(data_fd);

	return 0;
}

void output_flatfile_close(void)
{
	if (!data_fd)
		return;

	fclose(data_fd);
	data_fd = NULL;
}
