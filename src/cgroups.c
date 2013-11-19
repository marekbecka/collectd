/**
 * collectd - src/cgroups.c
 * Copyright (C) 2011  Michael Stapelberg
 * Copyright (C) 2013  Florian Forster
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the license is applicable.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Authors:
 *   Michael Stapelberg <michael at stapelberg.de>
 *   Florian Forster <octo at collectd.org>
 **/

#include "collectd.h"
#include "common.h"
#include "plugin.h"
#include "configfile.h"
#include "utils_mount.h"
#include "utils_ignorelist.h"

#define CGROUP_CPUACCT	0x01
#define CGROUP_MEMORY	0x02
#define CGROUP_BLKIO	0x04

#define CGROUP_SUBS_CPUACCT	1
#define CGROUP_SUBS_BLKIO	2
#define CGROUP_SUBS_MEMORY	3

static char const *cgroup_subsystems[] =
{
	"cpuacct",
	"blkio",
	"memory"
};

static char const *config_keys[] =
{
	"CGroup",
	"IgnoreSelected"
};
static int config_keys_num = STATIC_ARRAY_SIZE (config_keys);

static unsigned long pageshift = 0; 
static unsigned long ignore_subsystems = 0;

static ignorelist_t *il_cgroup = NULL;

static void cgroups_submit (char const *plugin_instance, const char *type,
		char const *type_instance, value_t *values, size_t values_len)
{
	value_list_t vl = VALUE_LIST_INIT;

	vl.values = values;
	vl.values_len = values_len;

	sstrncpy (vl.host, hostname_g, sizeof (vl.host));
	sstrncpy (vl.plugin, "cgroups", sizeof (vl.plugin));
	sstrncpy (vl.plugin_instance, plugin_instance,
			sizeof (vl.plugin_instance));
	sstrncpy (vl.type, type, sizeof (vl.type));
	sstrncpy (vl.type_instance, type_instance,
			sizeof (vl.type_instance));

	plugin_dispatch_values (&vl);
}

__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(2)))
__attribute__ ((nonnull(3)))
static void cgroups_submit_one (char const *plugin_instance, const char *type,
		char const *type_instance, value_t value)
{
	cgroups_submit(plugin_instance, type, type_instance, &value, 1);
} /* void cgroups_submit_one */

__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(2)))
__attribute__ ((nonnull(3)))
static void cgroups_submit_two (char const *plugin_instance, const char *type,
		char const *type_instance, value_t values[2])
{
	cgroups_submit(plugin_instance, type, type_instance, &values, 2);
} /* void cgroups_submit_two */

__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(2)))
static void read_cpuacct_stat (const char *cgroup_name, 
		void __attribute__((unused)) *payload, FILE *fh)
{
	char buf[128];

	while (fgets (buf, sizeof (buf), fh) != NULL)
	{
		char *fields[8];
		int numfields = 0;
		char *key;
		size_t key_len;
		value_t value;

		/* Expected format:
		 *
		 *   user: 12345
		 *   system: 23456
		 */
		strstripnewline (buf);
		numfields = strsplit (buf, fields, STATIC_ARRAY_SIZE (fields));
		if (numfields != 2)
			continue;

		key = fields[0];
		key_len = strlen (key);
		if (key_len < 2)
			continue;

		/* Strip colon off the first column */
		if (key[key_len - 1] != ':')
			continue;
		key[key_len - 1] = 0;

		if (!parse_value (fields[1], &value, DS_TYPE_DERIVE))
			continue;

		cgroups_submit_one (cgroup_name, "cpu", key, value);
	}
}

static value_t bytes_to_numpages (value_t bytes)
{
	return (bytes + (pagesize - 1)) >> pageshift;
/*	return (bytes + (pagesize - 1)) / pagesize; */
}

#define GOT_PGPGIN	0x01
#define GOT_PGPGOUT	0x02
#define GOT_PGFAULT	0x04
#define GOT_PGMAJFAULT	0x08

static void read_memory_stat (const char *cgroup_name,
		void __attribute__((unused)) *payload, FILE *fh)
{
	unsigned long parsed_values = 0;
	char buf[128];
	value_t pgpinout[2];
	value_t pgfaults[2];

	while (fgets (buf, sizeof (buf), fh) != NULL)
	{
                char *fields[4];
                int numfields = 0;
		value_t value;

		if (strncmp (buf, "total_", strlen ("total_")) == 0) 
			continue;

		if (strncmp (buf, "hierarchical_", strlen ("hierarchical_")) == 0)
			continue;

		strstripnewline (buf);
		numfields = strsplit (buf, fields, STATIC_ARRAY_SIZE (fields));
		if (numfields != 2)
			continue;

		if (strcmp (fields[0], "pgpgin") == 0)
		{
			if (parse_value (fields[1], pgpinout[0], DS_TYPE_DERIVE))
			{
				parsed_values |= GOT_PGPGIN;
			}
		}
		else if (strcmp (fields[0], "pgpgout") == 0)
		{
			if (parse_value (fields[1], pgpinout[1], DS_TYPE_DERIVE))
			{
				parsed_values |= GOT_PGPGOUT;
			}
		}
		else if (strcmp (fields[0], "pgfault") == 0)
		{
			if (parse_value (fields[1], pgfaults[0], DS_TYPE_DERIVE))
			{
				parsed_values |= GOT_PGFAULT;
			}			
		}
		else if (strcmp (fields[0], "pgmajfault") == 0)
		{
			if (parse_value (fields[1], pgfaults[1], DS_TYPE_DERIVE))
			{
				parsed_values |= GOT_PGMAJFAULT;
			}
		}
		else
		{
			value_t npages;

			if (!parse_value (fields[1], &value, DS_TYPE_GAUGE))
			{
				WARNING ("");
				continue;
			}

			npages = convert_to_pages(value);
			cgroups_submit_one (cgroup_name, "vmpage_number", fields[0], npages);
		}
	}

	if (parsed_values & (GOT_PGPGIN | GOT_PGPGOUT) == (GOT_PGPGIN | GOT_PGPGOUT))
	{
		cgroups_submit_two (cgroup_name, "vmpage_io", "memory", pgpinout);
	}

	if (parsed_values & (GOT_PGFAULT | GOT_PGMAJFAULT) == (GOT_PGFAULT | GOT_PGMAJFAULT))
	{
		cgroups_submit_two (cgroup_name, "vmpage_faults", "", pgfaults);
	}
}	

#undef GOT_PGPGIN
#undef GOT_PGPGOUT
#undef GOT_PGFAULT
#undef GOT_PGMAJFAULT

static int get_blkio_device (const char *buf, unsigned int *major, 
		unsigned int *minor)
{
	unsigned long maj, min;
	char *end;

	maj = strtoul(buf, &end, 10);
	if (end == buf || maj > 255)
	{
		WARNING ("");
		return 1;
	}

	if (*end != ':')
	{
		WARNING ("");
		return 1;
	}
	buf = end + 1;

	min = strtoul(buf, &end, 10);
        if (end == buf || min > 255)
        {
		WARNING ("");
		return 1;
        }

	*major = (unsigned int) maj;
	*minor = (unsigned int) min;

	return 0;
}

static int get_blkio_value_instance (char *buf, size_t buf_size,
		const char *prefix, unsigned int major, unsigned int minor)
{
	int res;

	res = snprintf(buf, buf_size, "%s-%u_%u", prefix, major, minor);
	if (res < 0) 
	{
		return 1;
	}

	return 0;
}

__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(2)))
static void read_blkio_rw (const char *cgroup, void *payload, FILE *fh)
{
	unsigned long parsed_values = 0;
	const char *prefix = payload->prefix;
	const char *value_type = payload->value_type;
	char buf[128];
	unsigned int blkdev[2];
	value_t rw[2];

	while (fgets (buf, sizeof (buf), fh) != NULL)
	{
                char *fields[4];
                int numfields; 
		unsigned int min = 0, maj = 0; 

		strstripnewline (buf);
		numfields = strsplit (buf, &fields, STATIC_ARRAY_SIZE (fields));
		if (numfields != 3)
			continue;

		if (!get_blk_device (fields[0], &maj, &min))
			continue;
		
		if (maj != blkdev[0] || min != blkdev[1])
		{
			blkdev[0] = maj;
			blkdev[1] = min;
			parsed_values = 0;
		}

		if (strcmp (fields[1], "Read") == 0)
		{
			if (!parse_value (fields[2], rw[0], DS_TYPE_DERIVE))
			{
				WARNING ("");
			}
		}
		else if (strcmp (fields[1], "Write") == 0)
		{
			if (!parse_value (fields[2], rw[1], DS_TYPE_DERIVE))
			{
				WARNING ("");
			}
		}

		if (parsed_values & (GOT_READ | GOT_WRITE) == GOT_READ | GOT_WRITE)
		{
			char instance[64];
			
			if (!get_blkio_value_instance (&instance, sizeof(instance), prefix, maj, min))
			{
				continue;
			}

			cgroups_submit_two (cgroup, value_type, instance, rw);
		}
	}
}

static void __read_blkio_single (const char *cgroup, const char *prefix, 
		const char *value_type, FILE *fh)
{
	char buf[128];

	while (fgets (buf, sizeof (buf), fh) != NULL)
	{
                int numfields;
		unsigned int maj, min;
		value_t value;
                char *fields[4];
		char instance[DATA_MAX_NAME_LEN];

		strstripnewline (buf);
		numfields = strsplit (buf, fields, STATIC_ARRAY_SIZE (fields));
		if (numfields != 2)
			continue;

		if (!get_blkio_device (fields[0], &maj, &min))
			continue;

		if (!parse_value (fields[1], &value, DS_TYPE_GAUGE))
			continue;

		if (!get_blkio_value_instance (&instance, sizeof(instance), 
				prefix, maj, min))
			continue;

		cgroups_submit_one (cgroup, value_type, instance, value);
	}
}

__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(2)))
static void read_blkio_single_no_prefix (const char *cgroup, void *payload, 
		FILE *fh)
{
	__read_blkio_single (cgroup, "", (char *)payload, fh);
}

__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(2)))
static void read_blkio_single (const char *cgroup, void *payload, FILE *fh)
{
	cgroup_handler_s *info = (cgroup_handler_s *) payload;

	__read_blkio_single (cgroup, info->value_prefix, info->value_type, fh);
}

static void __read_simple_value (const char *cgroup, 
		cgroup_handler_info_s *info, FILE *fh, int ds_type)
{
	char buf[16];
	value_t value;

	if (!fgets (buf, sizeof (buf), fh))
		return;

	strstripnewline (buf);
	if (!parse_value (buf, &value, ds_type))
		return;

	cgroups_submit_one (cgroup, info->value_type, info->value_prefix,
		value);
}

__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(2)))
static void read_simple_derive_cb(const char *cgroup, void *user_data, FILE *fh)
{
	__read_simple_value (fh, (cgroup_handler_info_s *) user_data, cgroup, 
			ds_type, DS_TYPE_DERIVE);
}

__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(2)))
static void read_simple_gauge_cb(const char *cgroup, void *user_data, FILE *fh)
{
	__read_simple_value (fh, (cgroup_handler_info_s *) user_data, cgroup, 
			ds_type, DS_TYPE_GAUGE);
}

static const char *DISK_MERGED = "disk_merged";
static const char *DISK_OCTETS = "disk_octets";
static const char *DISK_OPS = "disk_ops";
static const char *DISK_TIME = "disk_time";
static const char *DISK_OCTETS_THROTTLE = "disk_throttle_octets";
static const char *DISK_OPS_THROTTLE = "disk_throttle_ops";
static const char *MEMORY = "memory";
static const char *VMPAGE_ACTION = "vmpage_action";

static const cgroup_handler_s cpuacct[]
{
	{
		.filename	= "stat",
		.handler	= read_cpuacct_stat,
		.payload	=  NULL,
	},
};
/*
static const cgroup_handler_info_s blkio_queued_info =
{
        .value_type     = DISK_OPS,
        .value_prefix	= "queued",
};
*/
/*
static const cgroup_handler_info_s blkio_wait_info =
{
        .value_type     = DISK_TIME,
        .value_prefix	= "wait",
};
*/
static const cgroup_handler_s blkio[]
{
	{
		.filename	= "io_merged",
		.handler	= read_blkio_rw_no_prefix,
		.payload	= DISK_MERGED,
	},
/*
	{
		.filename	= "io_queued",
		.handler	= read_blkio_rw,
		.payload	= &blkio_queued_info,
	},
*/
	{
		.filename	= "io_service_bytes",
		.handler	= read_blkio_rw_no_prefix, 
		.payload	= DISK_OCTETS,
	},
	{
		.filename	= "io_service_time",
		.handler	= read_blkio_rw_no_prefix,
		.payload	= DISK_TIME,
	},
	{
		.filename	= "io_serviced",
		.handler	= read_blkio_rw_no_prefix,
		.payload	= DISK_OPS,
	},
/*	
	{
		.filename	= "io_wait_time",
		.handler	= read_blkio_rw,
		.payload	= &blkio_wait_info,
	}
*/
};

static const cgroup_handler_info_s failcnt_info =
{
        .value_type     = DISK_OCTETS,
        .value_prefix	= "throttled",
};

static const cgroup_handler_info_s failcnt_info =
{
        .value_type     = DISK_OPS,
        .value_prefix	= "throttled",
};

static const cgroup_handler_info_s failcnt_info =
{
        .value_type     = DISK_OCTETS_THROTTLE,
        .value_prefix	= "throttle_read",
};

static const cgroup_handler_info_s failcnt_info =
{
        .value_type     = DISK_OPS_THROTTLE,
        .value_prefix	= "throttle_read",
};

static const cgroup_handler_info_s failcnt_info =
{
        .value_type     = DISK_OCTETS_THROTTLE,
        .value_prefix	= "throttle_write",
};

static const cgroup_handler_info_s failcnt_data =
{
        .value_type     = DISK_OPS_THROTTLE,
        .value_prefix	= "throttle_write",
};

static const cgroup_handler_s blkio_throttle[]
{
	{
		.filename	= "io_service_bytes",
		.handler	= read_blkio_rw,
		.payload	= &throttle_bytes_data,
	},
	{
		.filename	= "io_serviced",
		.handler	= read_blkio_rw,
		.payload	= &throttle_iops_data,
	},
	{
		.filename	= "read_bps_device",
		.handler	= read_blkio_single, 
		.payload	= &throttle_read_bytes,
	},
	{
		.filename	= "read_iops_device",	
		.handler	= read_blkio_single, 
		.payload	= &throttle_read_ops,
	},
	{
		.filename	= "write_bps_device",
		.handler	= read_blkio_single,
		.payload	= &throttle_write_bytes,
	},
	{
		.filename	= "write_iops_device",
		.handler	= read_blkio_single,
		.payload	= &throttle_write_bytes,
	}
};

static const cgroup_handler_info_s failcnt_info = 
{	
	.value_type	= VMPAGE_ACTION,
	.value_prefix	= "failcnt",
};

static const cgroup_handler_info_s usage_info = 
{
	.value_type	= MEMORY,
	.value_prefix	= "usage",
};

static const cgroup_handler_info_s usage_watermark_info = 
{
	.value_type	= MEMORY,
	.value_prefix	= "usage_watermark",
};

static const cgroup_handler_info_s usage_limit_info = 
{
	.value_type	= MEMORY,
	.value_prefix	= "usage_limit",
};

static const cgroup_handler_s memory[] 
{
	{
		.filename	= "failcnt",
		.handler	= read_simple_derive, 
		.payload	= &failcnt_info,
	},
	{
		.filename	= "usage_in_bytes",
		.handler	= read_simple_gauge,
		.payload	= &usage_info,
	},
	{
		.filename	= "max_usage_in_bytes",
		.handler	= read_simple_gauge,
		.payload	= &usage_watermark_info,
	},
	{
		.filename	= "soft_limit_in_bytes",
		.handler	= read_simple_gauge,
		.payload	= &usage_softlimit_info,
	},
	{
		.filename	= "limit_in_bytes",
		.handler	= read_simple_gauge,
		.payload	= &usage_limit_info,
	},
};

static const cgroup_handler_s memory_stat[]
{
	{
		.filename	= "stat",
		.handler	= read_memory_stat,
		.payload	= NULL,
	},
/*	
	{
		.filename	= "numa.stat",
		.handler	=  read_memory_numa_stat,
		.payload	=  NULL
	},
*/
};

static const cgroup_handler_s memory_extended[]
{
	{
		.filename	= "failcnt",
		.handler	= read_simple_derive,
		.payload	= &failcnt_info,
	},
	{
		.filename	= "usage_in_bytes",
		.handler	= read_simple_gauge,
		.payload	= &usage_info,
	},
	{
		.filename	= "max_usage_in_bytes",
		.handler	= read_simple_gauge,
		.payload	= &usage_watermark_info,
	},
	{
		.filename	= "limit_in_bytes",
		.handler	= read_simple_gauge,
		.payload	= &usage_limit_info,
	},
};

static void handle_subsystem(const cgroup_subsystem_handler_s **handlers,
		size_t num_handlers, const char *mountpoint,
		const char *cgroup_name, const char *subsystem_name,
		const char *prefix)
{
	for (size_t n = 0; n < num_handlers; n++)
	{
		FILE *file;
		cgroup_handler_s *h;
		char path[PATH_MAX];

		ssnprintf (path, sizeof (path), "%s/%s/%s.%s", mountpoint,
				cgroup_name, subsystem_name, h->filename);

		if (!(file = fopen (path, "r")))
			continue;

		h->handler (cgroup_name, h->payload, fh, prefix);

		fclose (file);
	}
}

static int do_cgroup (const char *mountpoint, char const *cgroup_name,
		unsigned long subsystems)
{
	int status;

	if (ignorelist_match (il_cgroup, cgroup_name))
		return (0);

	if (subsystems & CGROUP_CPUACCT)
	{
		handle_subsystem (cpuacct, mountpoint, cgroup_name, "cpuacct", 
				"");
	}

	if (subsystems & CGROUP_MEMORY)
	{
		handle_subsystem (memory, mountpoint, cgroup_name, "memory", 
				"");

		if (memory_extended)
			handle_subsystem (memory_stat, mountpoint, cgroup_name, 
					"memory", "");

		if (memory_extended)
			handle_subsystem (memory_extended, mountpoint, 
					cgroup_name, "memory.kmem", "kmem_");

		if (memory_extended)
			handle_subsystem (memory_extended, mountpoint, 
					cgroup_name, "memory.kmem.tcp", 
					"kmem_tcp_");

		if (memory_extended)
			handle_subsystem (memory_extended, mountpoint, 
					cgroup_name, "memory.memsw", "memsw_");
	}

	if (subsystems & CGROUP_BLKIO)
	{
		handle_subsystem (blkio, mountpoint, cgroup_name, "blkio", "");

		if (blkio_thtottling)
			handle_subsystem (blkio_throttle, mountpoint, 
					cgroup_name, "blkio.throttle", "");
	}

	return (0);
} /* int read_cpuacct_procs */

/*
 * Gets called for every file/folder in /sys/fs/cgroup/cpu,cpuacct (or
 * whereever cpuacct is mounted on the system). Calls walk_directory with the
 * read_cpuacct_procs callback on every folder it finds, such as "system".
 */
static int cgroups_read_root_dir (const char *dirname, const char *filename,
		void *user_data)
{
	char abs_path[PATH_MAX];
	struct stat statbuf;

	ssnprintf (abs_path, sizeof (abs_path), "%s/%s", dirname, filename);

	status = lstat (abs_path, &statbuf);
	if (status != 0)
	{
		ERROR ("cgroups plugin: stat (%s) failed.", abs_path);
		return (-1);
	}

	if (S_ISDIR (statbuf.st_mode))
	{
		do_cgroup (dirname, filename, (unsigned long) user_data);
	}

	return (0);
}

static int cgroups_init (void)
{
	long pagesize;

	if (il_cgroup == NULL)
		il_cgroup = ignorelist_create (1);

	pagesize = sysconf (_SC_PAGESIZE);
	if (pagesize < 0)
	{
		ERROR ("cgroups plugin: getting size of a page failed, using default 4096.");
		pagesize = 4096L;
	}

	pageshift = ffs (pagesize);

	return (0);
}

static int cgroups_config (const char *key, const char *value)
{
	cgroups_init ();

	if (strcasecmp (key, "CGroup") == 0)
	{
		if (ignorelist_add (il_cgroup, value))
			return (1);
		return (0);
	}
	else if (strcasecmp (key, "IgnoreSelected") == 0)
	{
		if (IS_TRUE (value))
			ignorelist_set_invert (il_cgroup, 0);
		else
			ignorelist_set_invert (il_cgroup, 1);
		return (0);
	}

	return (-1);
}

static int cgroups_read (void)
{
	cu_mount_t *mnt_list;
	cu_mount_t *mnt_ptr;
	_Bool cgroup_found = 0;

	mnt_list = NULL;
	if (cu_mount_getlist (&mnt_list) == NULL)
	{
		ERROR ("cgroups plugin: cu_mount_getlist failed.");
		return (-1);
	}

	for (mnt_ptr = mnt_list; mnt_ptr != NULL; mnt_ptr = mnt_ptr->next)
	{
		unsigned long mounted_subsystems = 0;

		/* Find the cgroup mountpoints. */
		if (strcmp(mnt_ptr->type, "cgroup") != 0)
			continue;

		for (size_t n = 0; n < STATIC_ARRAY_SIZE (subsystems); n++)
		{
			if (cu_mount_getoptionvalue (mnt_ptr->options, 
					subsystems[i]))
			{
				mounted_subsystems |= 1 << n; 
			}
		}

		if (mounted_subsystems == 0)
			continue;

		walk_directory (mnt_ptr->dir, cgroups_read_root_dir, 
				mounted_subsystems, /* include_hidden = */ 0);

		cgroup_found = 1;
	}

	cu_mount_freelist (mnt_list);

	if (!cgroup_found)
	{
		WARNING ("cgroups plugin: Unable to find cgroup "
				"mount-point with the \"cpuacct\" option.");
		return (-1);
	}

	return (0);
} /* int cgroup_read */

void module_register (void)
{
	plugin_register_config ("cgroups", cgroups_config,
			config_keys, config_keys_num);
	plugin_register_init ("cgroups", cgroups_init);
	plugin_register_read ("cgroups", cgroups_read);
} /* void module_register */
