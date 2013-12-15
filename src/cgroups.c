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

enum cgroup_subsystem
{
	CGROUP_SUBSYSTEM_CPUACCT = 0,
	CGROUP_SUBSYSTEM_BLKIO,
	CGROUP_SUBSYSTEM_MEMORY
};

#define CGROUP_MOUNT_CPUACCT		(1UL << CGROUP_SUBSYSTEM_CPUACCT)
#define CGROUP_MOUNT_BLKIO		(1UL << CGROUP_SUBSYSTEM_BLKIO)
#define CGROUP_MOUNT_MEMORY		(1UL << CGROUP_SUBSYSTEM_MEMORY)

static char *cgroup_subsystem_str[] =
{
	"cpuacct",
	"blkio",
	"memory"
};

enum cgroup_set
{
	CGROUP_SET_CPUACCT_BASIC = 0,
	CGROUP_SET_BLKIO_BASIC,
	CGROUP_SET_BLKIO_THROTTLE,
	CGROUP_SET_MEMORY_BASIC,
	CGROUP_SET_MEMORY_STAT,
	CGROUP_SET_MEMORY_KERNEL,
	CGROUP_SET_MEMORY_TCP,
	CGROUP_SET_MEMORY_SWAP
};

#define CGROUP_DO_CPUACCT_BASIC		(1UL << CGROUP_SET_CPUACCT_BASIC)

#define CGROUP_DO_BLKIO_BASIC		(1UL << CGROUP_SET_BLKIO_BASIC)
#define CGROUP_DO_BLKIO_THROTTLE	(1UL << CGROUP_SET_BLKIO_THROTTLE)

#define CGROUP_DO_MEMORY_BASIC		(1UL << CGROUP_SET_MEMORY_BASIC)
#define CGROUP_DO_MEMORY_STAT		(1UL << CGROUP_SET_MEMORY_STAT)
#define CGROUP_DO_MEMORY_KERNEL		(1UL << CGROUP_SET_MEMORY_KERNEL)
#define CGROUP_DO_MEMORY_TCP		(1UL << CGROUP_SET_MEMORY_TCP)
#define CGROUP_DO_MEMORY_SWAP		(1UL << CGROUP_SET_MEMORY_SWAP)

static const char *cgroup_set_str[] =
{
	"cpuacct",
	"blkio",
	"blkio.throttle",
	"memory",
	"memory.vmem",
	"memory.kmem",
	"memory.kmem.tcp",
	"memory.memsw"
};

#define CGROUP_DO_DEFAULT		( CGROUP_DO_CPUACCT_BASIC \
					| CGROUP_DO_BLKIO_BASIC \
					| CGROUP_DO_MEMORY_BASIC )

#define CGROUP_DO_ALL			( CGROUP_DO_CPUACCT_BASIC \
					| CGROUP_DO_BLKIO_BASIC \
					| CGROUP_DO_BLKIO_THROTTLE \
					| CGROUP_DO_MEMORY_BASIC \
					| CGROUP_DO_MEMORY_STAT \
					| CGROUP_DO_MEMORY_KERNEL \
					| CGROUP_DO_MEMORY_TCP \
					| CGROUP_DO_MEMORY_SWAP )

static char const *config_keys[] =
{
	"CGroup",
	"IgnoreSelected",
	"Subsystems"
};

typedef struct cgroup_handler_s 
{
	char *filename;
	int (*func) (const char *cgroup, FILE *fh, void *payload,
			void *custom_data);
	void *payload;

} cgroup_handler_t;

typedef struct cgroup_handler_info_s
{
	char *value_type;
	char *value_prefix;

} cgroup_handler_info_t;


static int config_keys_num = STATIC_ARRAY_SIZE (config_keys);

static unsigned long do_subsystems = CGROUP_DO_DEFAULT;

static unsigned long pageshift = 0; 

static ignorelist_t *il_cgroup = NULL;


static int test_bits (unsigned long flags, unsigned long mask)
{
	return ((flags & mask) == mask);
}

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
	cgroups_submit(plugin_instance, type, type_instance, values, 2);
} /* void cgroups_submit_two */

__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(2)))
static int read_cpuacct_stat (const char *cgroup_name, FILE *fh,
		void __attribute__((unused)) *payload,
		void __attribute__((unused)) *custom_data)
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

	return 0;
}

static value_t bytes_to_numpages (value_t bytes)
{
	value_t ret;

	ret.gauge = ((unsigned long) bytes.gauge + ((1UL << pageshift) - 1)) >> pageshift;
/*	ret.gauge = bytes.gauge / pagesize; */

	return ret;
}

static int read_memory_stat (const char *cgroup_name, FILE *fh,
		void __attribute__((unused)) *payload,
		void __attribute__((unused)) *custom_data)
{
	unsigned long parsed_values = 0;
	char buf[128];
	value_t inout[2];
	value_t faults[2];

#define GOT_PGPGIN	0x01
#define GOT_PGPGOUT	0x02
#define GOT_PGFAULT	0x04
#define GOT_PGMAJFAULT	0x08

#define STR_STARTS_WITH(a, b) strncmp (a, b, strlen (b))

	while (fgets (buf, sizeof (buf), fh) != NULL)
	{
                char *fields[4];
                int numfields = 0;
		value_t value;


		if (STR_STARTS_WITH (buf, "total_") == 0) 
			continue;

		if (STR_STARTS_WITH (buf, "hierarchical_") == 0)
			continue;

		strstripnewline (buf);
		numfields = strsplit (buf, fields, STATIC_ARRAY_SIZE (fields));
		if (numfields != 2)
			continue;

		if (strcmp (fields[0], "pgpgin") == 0)
		{
			if (parse_value (fields[1], &inout[0], DS_TYPE_DERIVE))
				parsed_values |= GOT_PGPGIN;
		}
		else if (strcmp (fields[0], "pgpgout") == 0)
		{
			if (parse_value (fields[1], &inout[1], DS_TYPE_DERIVE))
				parsed_values |= GOT_PGPGOUT;
		}
		else if (strcmp (fields[0], "pgfault") == 0)
		{
			if (parse_value (fields[1], &faults[0], DS_TYPE_DERIVE))
				parsed_values |= GOT_PGFAULT;
		}
		else if (strcmp (fields[0], "pgmajfault") == 0)
		{
			if (parse_value (fields[1], &faults[1], DS_TYPE_DERIVE))
				parsed_values |= GOT_PGMAJFAULT;
		}
		else
		{
			if (!parse_value (fields[1], &value, DS_TYPE_GAUGE))
			{
				DEBUG ("cgroups plugin: unable to parse numeric"
						"value from field ");
				continue;
			}

			cgroups_submit_one (cgroup_name, "vmpage_number", 
					fields[0], bytes_to_numpages(value));
		}
	}

	if (test_bits (parsed_values, GOT_PGPGIN | GOT_PGPGOUT))
		cgroups_submit_two (cgroup_name, "vmpage_io", "memory", inout);
	else
		DEBUG ("cgroups plugin: page io not found in a status");

	if (test_bits (parsed_values, GOT_PGFAULT | GOT_PGMAJFAULT))
		cgroups_submit_two (cgroup_name, "vmpage_faults", "", faults);
	else
		DEBUG ("cgroups plugin: page faults not found in a status");

#undef GOT_PGPGIN
#undef GOT_PGPGOUT
#undef GOT_PGFAULT
#undef GOT_PGMAJFAULT
#undef STR_STARTS_WITH

	return 0;
}

static int get_blkio_device (const char *buf, unsigned int *major, 
		unsigned int *minor)
{
	unsigned long maj, min;
	char *end;

	maj = strtoul (buf, &end, 10);
	if (end == buf || maj > 255)
		goto fail;

	if (*end != ':')
		goto fail;

	buf = end + 1;

	min = strtoul (buf, &end, 10);
        if (end == buf || min > 255)
		goto fail;

	*major = (unsigned int) maj;
	*minor = (unsigned int) min;

	return (0);

fail:
	DEBUG ("cgroups plugin: invalid block device %s");
	return (-1);
}

static void get_blkio_value_instance (char *buf, size_t buf_size,
		const char *prefix, unsigned int major, unsigned int minor)
{
	int res;

	if (prefix != NULL)
	{
		res = ssnprintf(buf, buf_size, "%s_%u:%u", prefix, major, minor);
		if (res >= buf_size)
			DEBUG ("cgroups plugin: truncated value %s_%u:%u",
					prefix, major, minor);
	}
	else
	{
		res = ssnprintf(buf, buf_size, "%u:%u", major, minor);	
		if (res >= buf_size)
			DEBUG ("cgroups plugin: truncated value %u:%u",
					major, minor); 
	}
}

__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(2)))
__attribute__ ((nonnull(4)))
static int __read_blkio_rw (const char *cgroup, FILE *fh, const char *prefix,
		const char *value_type)
{
	unsigned long parsed_values = 0;
	char buf[128];
	unsigned blkdev[2];
	value_t rw[2];

#define GOT_READ	0x01
#define GOT_WRITE	0x02

	while (fgets (buf, sizeof (buf), fh) != NULL)
	{
                char *fields[4];
                int numfields; 
		unsigned min = 0, maj = 0; 

		strstripnewline (buf);
		numfields = strsplit (buf, fields, STATIC_ARRAY_SIZE (fields));
		if (numfields != 3)
			continue;

		if (!get_blkio_device (fields[0], &maj, &min))
			continue;
		
		if (maj != blkdev[0] || min != blkdev[1])
		{
			blkdev[0] = maj;
			blkdev[1] = min;
			parsed_values = 0;
		}

		if (strcmp (fields[1], "Read") == 0)
		{
			if (parse_value (fields[2], &rw[0], DS_TYPE_DERIVE))
				parsed_values |= GOT_READ;
			else
				DEBUG ("cgroups plugin: unable to parse "
						"blkio %s on device %u:%u.",
						"reads", maj, min);
		}
		else if (strcmp (fields[1], "Write") == 0)
		{
			if (parse_value (fields[2], &rw[1], DS_TYPE_DERIVE))
				parsed_values |= GOT_WRITE;
			else
				DEBUG ("cgroups plugin: unable to parse "
						"blkio %s on device %u:%u.",
						"writes", maj, min);
		}

		if (test_bits (parsed_values, GOT_READ | GOT_WRITE))
		{
			char instance[DATA_MAX_NAME_LEN];
			
			get_blkio_value_instance (instance, sizeof(instance), 
					prefix, maj, min);
			cgroups_submit_two (cgroup, value_type, instance, rw);
		}
	}

#undef GOT_READ
#undef GOT_WRITE

	return 0;
}

__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(2)))
__attribute__ ((nonnull(3)))
static int read_blkio_rw_no_prefix (const char *cgroup, FILE *fh, void *payload,
                void __attribute__((unused)) *custom_data)
{
	return __read_blkio_rw (cgroup, fh, NULL, (const char *) payload);
}

__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(2)))
__attribute__ ((nonnull(3)))
static int read_blkio_rw (const char *cgroup, FILE *fh, void *payload,
                void __attribute__((unused)) *custom_data)
{
        cgroup_handler_info_t *i = (cgroup_handler_info_t *) payload;

	return __read_blkio_rw (cgroup, fh, i->value_prefix, i->value_type);
}

static int __read_blkio_single (const char *cgroup, FILE *fh,
		const char *prefix, const char *value_type)
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
		{
			DEBUG ("cgroups plugin: unable to parse value: %s"
					"on blkio device %u:%u",
					fields[1], maj, min);
			continue;
		}

		get_blkio_value_instance (instance, sizeof(instance), 
				prefix, maj, min);
		cgroups_submit_one (cgroup, value_type, instance, value);
	}

	return 0;
}
/*
__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(2)))
__attribute__ ((nonnull(3)))
static int read_blkio_single_no_prefix (const char *cgroup, FILE *fh, 
		void *payload, void __attribute__((unused)) *custom_data)
{
	return __read_blkio_single (cgroup, fh, NULL, (const char *) payload);
}
*/
__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(2)))
__attribute__ ((nonnull(3)))
static int read_blkio_single (const char *cgroup, FILE *fh,
		void *payload, void __attribute__((unused)) *custom_data)
{
	cgroup_handler_info_t *i = (cgroup_handler_info_t *) payload;

	return __read_blkio_single (cgroup, fh, i->value_prefix, i->value_type);
}

__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(2)))
__attribute__ ((nonnull(3)))
static int __read_simple_value (const char *cgroup, FILE *fh, 
		cgroup_handler_info_t *info, int ds_type, 
		const char *custom_prefix)
{
	value_t value;
	const char *type_instance;
	char buf[16];
	char combined_prefix[DATA_MAX_NAME_LEN];

	if (!fgets (buf, sizeof (buf), fh))
		return (-1);

	strstripnewline (buf);
	if (!parse_value (buf, &value, ds_type))
		return (-1);

	if (custom_prefix != NULL)
	{
		if (info->value_prefix != NULL)
		{
			int res = ssnprintf (combined_prefix, 
					sizeof (combined_prefix), "%s_%s", 
					custom_prefix, info->value_prefix);

			if (res >= sizeof (combined_prefix))
				DEBUG ("cgroup plugin: instance type "
						"truncated %s_%s",
						custom_prefix, 
						info->value_prefix);

			type_instance = combined_prefix;
		}
		else
			type_instance = custom_prefix;
	}
	else
		type_instance = info->value_prefix;

	cgroups_submit_one (cgroup, info->value_type, type_instance, value);
	
	return 0;
}

__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(2)))
__attribute__ ((nonnull(3)))
static int read_simple_derive (const char *cgroup, FILE *fh, void *payload, 
		void *custom_data)
{
	cgroup_handler_info_t *info = (cgroup_handler_info_t *) payload;

	return	__read_simple_value (cgroup, fh, info, DS_TYPE_DERIVE,
			custom_data);
}

__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(2)))
__attribute__ ((nonnull(3)))
static int read_simple_gauge (const char *cgroup, FILE *fh, void *payload,
		void *custom_data)
{
	cgroup_handler_info_t *info = (cgroup_handler_info_t *) payload;

	return __read_simple_value (cgroup, fh, info, DS_TYPE_GAUGE,
			custom_data);
}

static const cgroup_handler_t cpuacct[] =
{
	{
		.filename	= "stat",
		.func		= read_cpuacct_stat,
		.payload	= NULL,
	},
};
/*
static const cgroup_handler_info_t blkio_queued_info =
{
        .value_type     = "disk_ops",
        .value_prefix	= "queued",
};
*/
/*
static const cgroup_handler_info_t blkio_wait_info =
{
        .value_type     = "disk_latency",
        .value_prefix	= "wait",
};
*/
static const cgroup_handler_t blkio[] =
{
	{
		.filename	= "io_merged",
		.func		= read_blkio_rw_no_prefix,
		.payload	= "disk_merged",
	},
/*
	{
		.filename	= "io_queued",
		.func		= read_blkio_rw,
		.payload	= blkio_queued_info,
	},
*/
	{
		.filename	= "io_service_bytes",
		.func		= read_blkio_rw_no_prefix, 
		.payload	= "disk_octets",
	},
	{
		.filename	= "io_service_time",
		.func		= read_blkio_rw_no_prefix,
		.payload	= "disk_time",
	},
	{
		.filename	= "io_serviced",
		.func		= read_blkio_rw_no_prefix,
		.payload	= "disk_ops",
	},
/*	
	{
		.filename	= "io_wait_time",
		.func		= read_blkio_rw,
		.payload	= blkio_wait_info,
	}
*/
};

static const cgroup_handler_info_t throttle_bytes_data =
{
        .value_type     = "disk_octets",
        .value_prefix	= "throttled",
};

static const cgroup_handler_info_t throttle_iops_data =
{
        .value_type     = "disk_ops",
        .value_prefix	= "throttled",
};

static const cgroup_handler_info_t throttle_read_bytes =
{
        .value_type     = "bytes",
        .value_prefix	= "throttle_read",
};

static const cgroup_handler_info_t throttle_read_ops =
{
        .value_type     = "requests",
        .value_prefix	= "throttle_read",
};

static const cgroup_handler_info_t throttle_write_bytes =
{
        .value_type     = "bytes",
        .value_prefix	= "throttle_write",
};

static const cgroup_handler_info_t throttle_write_ops =
{
        .value_type     = "requests",
        .value_prefix	= "throttle_write",
};

static const cgroup_handler_t blkio_throttle[] =
{
	{
		.filename	= "io_service_bytes",
		.func		= read_blkio_rw,
		.payload	= (void *) &throttle_bytes_data,
	},
	{
		.filename	= "io_serviced",
		.func		= read_blkio_rw,
		.payload	= (void *) &throttle_iops_data,
	},
	{
		.filename	= "read_bps_device",
		.func		= read_blkio_single, 
		.payload	= (void *) &throttle_read_bytes,
	},
	{
		.filename	= "read_iops_device",	
		.func		= read_blkio_single, 
		.payload	= (void *) &throttle_read_ops,
	},
	{
		.filename	= "write_bps_device",
		.func		= read_blkio_single,
		.payload	= (void *) &throttle_write_bytes,
	},
	{
		.filename	= "write_iops_device",
		.func		= read_blkio_single,
		.payload	= (void *) &throttle_write_ops,
	}
};

static const cgroup_handler_info_t failcnt_info = 
{	
	.value_type	= "vmpage_faults",
	.value_prefix	= NULL,
};

static const cgroup_handler_info_t usage_info = 
{
	.value_type	= "memory",
	.value_prefix	= "used",
};

static const cgroup_handler_info_t usage_watermark_info = 
{
	.value_type	= "memory",
	.value_prefix	= "usage_watermark",
};

static const cgroup_handler_info_t usage_softlimit_info = 
{
	.value_type	= "memory",
	.value_prefix	= "usage_softlimit",
};

static const cgroup_handler_info_t usage_limit_info = 
{
	.value_type	= "memory",
	.value_prefix	= "usage_limit",
};

static const cgroup_handler_t memory[] =
{
	{
		.filename	= "failcnt",
		.func		= read_simple_derive, 
		.payload	= (void *) &failcnt_info,
	},
	{
		.filename	= "usage_in_bytes",
		.func		= read_simple_gauge,
		.payload	= (void *) &usage_info,
	},
	{
		.filename	= "max_usage_in_bytes",
		.func		= read_simple_gauge,
		.payload	= (void *) &usage_watermark_info,
	},
	{
		.filename	= "soft_limit_in_bytes",
		.func		= read_simple_gauge,
		.payload	= (void *) &usage_softlimit_info,
	},
	{
		.filename	= "limit_in_bytes",
		.func		= read_simple_gauge,
		.payload	= (void *) &usage_limit_info,
	},
};

static const cgroup_handler_t memory_stat[] =
{
	{
		.filename	= "stat",
		.func		= read_memory_stat,
		.payload	= NULL,
	},
/*	
	{
		.filename	= "numa.stat",
		.func		=  read_memory_numa_stat,
		.payload	=  NULL
	},
*/
};

static const cgroup_handler_t memory_ext[] =
{
	{
		.filename	= "failcnt",
		.func		= read_simple_derive,
		.payload	= (void *) &failcnt_info,
	},
	{
		.filename	= "usage_in_bytes",
		.func		= read_simple_gauge,
		.payload	= (void *) &usage_info,
	},
	{
		.filename	= "max_usage_in_bytes",
		.func		= read_simple_gauge,
		.payload	= (void *) &usage_watermark_info,
	},
	{
		.filename	= "limit_in_bytes",
		.func		= read_simple_gauge,
		.payload	= (void *) &usage_limit_info,
	},
};

__attribute__ ((nonnull(1)))
__attribute__ ((nonnull(3)))
__attribute__ ((nonnull(4)))
__attribute__ ((nonnull(5)))
static int handle_subsystem(const cgroup_handler_t *handlers,
		size_t num_handlers, const char *mountpoint,
		const char *cgroup_name, const char *subsystem_name,
		void *custom_data)
{
	int fails = 0;
	size_t n;

	for (n = 0; n < num_handlers; n++)
	{
		FILE *fh;
		cgroup_handler_t h = handlers[n];
		char path[PATH_MAX];

		ssnprintf (path, sizeof (path), "%s/%s/%s.%s", mountpoint,
				cgroup_name, subsystem_name, h.filename);

		if (!(fh = fopen (path, "r")))
		{
			WARNING ("cgroup plugin: Unable to open file: %s", 
					path);
			fails++;
			continue;
		}

		if (!h.func (cgroup_name, fh, h.payload, custom_data))
			fails++;

		fclose (fh);
	}

	return (num_handlers - fails);
}

static void do_cgroup (const char *mountpoint, char const *cgroup_name,
		unsigned long mounted_subsystems)
{
	if (ignorelist_match (il_cgroup, cgroup_name))
		return;

#define DO_SUBSYSTEM(subsystem, handlers, subsystem_name, custom_data) do { \
	if (do_subsystems & subsystem) { \
		int succ = handle_subsystem (handlers, \
				STATIC_ARRAY_SIZE (handlers), mountpoint, \
				cgroup_name, subsystem_name, custom_data); \
		if (succ <= 0) \
			do_subsystems &= ~subsystem; \
	} \
} while (0); 

	if (mounted_subsystems & CGROUP_SUBSYSTEM_CPUACCT)
	{
		DO_SUBSYSTEM (CGROUP_DO_CPUACCT_BASIC, cpuacct, "cpuacct", NULL);
	}

	if (mounted_subsystems & CGROUP_SUBSYSTEM_MEMORY)
	{
		DO_SUBSYSTEM (CGROUP_DO_MEMORY_BASIC, memory, "memory", NULL);

		DO_SUBSYSTEM (CGROUP_DO_MEMORY_STAT, memory_stat, "memory", 
				NULL);

		DO_SUBSYSTEM (CGROUP_DO_MEMORY_KERNEL, memory_ext, 
				"memory.kmem", "kernel_");

		DO_SUBSYSTEM (CGROUP_DO_MEMORY_TCP, memory_ext, 
				"memory.kmem.tcp", "tcp_");

		DO_SUBSYSTEM (CGROUP_DO_MEMORY_SWAP, memory_ext, 
				"memory.memsw", "memsw_");
	}

	if (mounted_subsystems & CGROUP_SUBSYSTEM_BLKIO)
	{
		DO_SUBSYSTEM (CGROUP_DO_BLKIO_BASIC, blkio, "blkio", NULL);

		DO_SUBSYSTEM (CGROUP_DO_BLKIO_THROTTLE, blkio_throttle, 
				"blkio.throttle", NULL);
	}

#undef DO_SUBSYSTEM

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

	if (!lstat (abs_path, &statbuf))
	{
		ERROR ("cgroups plugin: stat (%s) failed.", abs_path);
		return (-1);
	}

	if (S_ISDIR (statbuf.st_mode))
		do_cgroup (dirname, filename, (unsigned long) user_data);

	return (0);
}

static int cgroups_init (void)
{
	long pagesize;

	if (il_cgroup == NULL)
		il_cgroup = ignorelist_create (1);

	pagesize = sysconf (_SC_PAGESIZE);
	if (pagesize <= 0)
		goto init_failed;

	pageshift = ffs (pagesize);
	if (pageshift <= 0)
		goto init_failed;

	return (0);

init_failed:
	ERROR ("cgroups plugin: unable to determine system pagesize.");
	return (-1);
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
	else if (strcasecmp (key, "Subsystem") == 0)
	{
		int i;

		for (i = 0; i < STATIC_ARRAY_SIZE (cgroup_set_str); i++)
		{
			if (strcmp(value, cgroup_set_str[i]))
			{
				do_subsystems |= 1UL << i;
				return (0);
			}
		}

		return (1);
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
		int i;
		unsigned long mounted_subsystems = 0;

		/* Find the cgroup mountpoints. */
		if (strcmp (mnt_ptr->type, "cgroup") != 0)
			continue;

		for (i = 0; i < STATIC_ARRAY_SIZE (cgroup_subsystem_str); i++)
		{
			if (cu_mount_getoptionvalue (mnt_ptr->options, 
					cgroup_subsystem_str[i]))
			{
				mounted_subsystems |= 1UL << i; 
			}
		}

		if (mounted_subsystems == 0)
			continue;

		walk_directory (mnt_ptr->dir, cgroups_read_root_dir, 
				(void *) mounted_subsystems, /* include_hidden = */ 0);

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
