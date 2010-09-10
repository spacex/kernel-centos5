/*
 *  acpi_numa.c - ACPI NUMA support
 *
 *  Copyright (C) 2002 Takayoshi Kochi <t-kochi@bq.jp.nec.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/acpi.h>
#include <acpi/acpi_bus.h>
#include <acpi/acmacros.h>

#define ACPI_NUMA	0x80000000
#define _COMPONENT	ACPI_NUMA
ACPI_MODULE_NAME("numa")

static nodemask_t nodes_found_map = NODE_MASK_NONE;
#define PXM_INVAL	-1
#define NID_INVAL	-1

/* maps to convert between proximity domain and logical node ID */
int __cpuinitdata pxm_to_node_map[MAX_PXM_DOMAINS]
				= { [0 ... MAX_PXM_DOMAINS - 1] = NID_INVAL };
int __cpuinitdata node_to_pxm_map[MAX_NUMNODES]
				= { [0 ... MAX_NUMNODES - 1] = PXM_INVAL };

extern int __init acpi_table_parse_madt_family(enum acpi_table_id id,
					       unsigned long madt_size,
					       int entry_id,
					       acpi_madt_entry_handler handler,
					       unsigned int max_entries);

int __cpuinit pxm_to_node(int pxm)
{
	if (pxm < 0)
		return NID_INVAL;
	return pxm_to_node_map[pxm];
}

int __cpuinit node_to_pxm(int node)
{
	if (node < 0)
		return PXM_INVAL;
	return node_to_pxm_map[node];
}

int __cpuinit acpi_map_pxm_to_node(int pxm)
{
	int node = pxm_to_node_map[pxm];

	if (node < 0){
		if (nodes_weight(nodes_found_map) >= MAX_NUMNODES)
			return NID_INVAL;
		node = first_unset_node(nodes_found_map);
		pxm_to_node_map[pxm] = node;
		node_to_pxm_map[node] = pxm;
		node_set(node, nodes_found_map);
	}

	return node;
}

void __cpuinit acpi_unmap_pxm_to_node(int node)
{
	int pxm = node_to_pxm_map[node];
	pxm_to_node_map[pxm] = NID_INVAL;
	node_to_pxm_map[node] = PXM_INVAL;
	node_clear(node, nodes_found_map);
}

void __init acpi_table_print_srat_entry(acpi_table_entry_header * header)
{

	ACPI_FUNCTION_NAME("acpi_table_print_srat_entry");

	if (!header)
		return;

	switch (header->type) {

	case ACPI_SRAT_PROCESSOR_AFFINITY:
#ifdef ACPI_DEBUG_OUTPUT
		{
			struct acpi_table_processor_affinity *p =
			    (struct acpi_table_processor_affinity *)header;
			ACPI_DEBUG_PRINT((ACPI_DB_INFO,
					  "SRAT Processor (id[0x%02x] eid[0x%02x]) in proximity domain %d %s\n",
					  p->apic_id, p->lsapic_eid,
					  p->proximity_domain,
					  p->flags.
					  enabled ? "enabled" : "disabled"));
		}
#endif				/* ACPI_DEBUG_OUTPUT */
		break;

	case ACPI_SRAT_MEMORY_AFFINITY:
#ifdef ACPI_DEBUG_OUTPUT
		{
			struct acpi_table_memory_affinity *p =
			    (struct acpi_table_memory_affinity *)header;
			ACPI_DEBUG_PRINT((ACPI_DB_INFO,
					  "SRAT Memory (0x%08x%08x length 0x%08x%08x type 0x%x) in proximity domain %d %s%s\n",
					  p->base_addr_hi, p->base_addr_lo,
					  p->length_hi, p->length_lo,
					  p->memory_type, p->proximity_domain,
					  p->flags.
					  enabled ? "enabled" : "disabled",
					  p->flags.
					  hot_pluggable ? " hot-pluggable" :
					  ""));
		}
#endif				/* ACPI_DEBUG_OUTPUT */
		break;

	default:
		printk(KERN_WARNING PREFIX
		       "Found unsupported SRAT entry (type = 0x%x)\n",
		       header->type);
		break;
	}
}

/*
 * A lot of BIOS fill in 10 (= no distance) everywhere. This messes
 * up the NUMA heuristics which wants the local node to have a smaller
 * distance than the others.
 * Do some quick checks here and only use the SLIT if it passes.
 */
static __init int slit_valid(struct acpi_table_slit *slit)
{
	int i, j;
	int d = slit->localities;
	for (i = 0; i < d; i++) {
 		for (j = 0; j < d; j++)  {
 			u8 val = slit->entry[d*i + j];
 			if (i == j) {
 				if (val != LOCAL_DISTANCE)
 					return 0;
 			} else if (val <= LOCAL_DISTANCE)
 				return 0;
 		}
 	}
 	return 1;
}

static int __init acpi_parse_slit(unsigned long phys_addr, unsigned long size)
{
	struct acpi_table_slit *slit;

	if (!phys_addr || !size)
		return -EINVAL;

	slit = (struct acpi_table_slit *)__va(phys_addr);

	if (!slit_valid(slit)) {
		printk(KERN_INFO "ACPI: SLIT table looks invalid. Not used.\n");
		return -EINVAL;
	}
	acpi_numa_slit_init(slit);

	return 0;
}

static int __init
acpi_parse_processor_affinity(acpi_table_entry_header * header,
			      const unsigned long end)
{
	struct acpi_table_processor_affinity *processor_affinity;

	processor_affinity = (struct acpi_table_processor_affinity *)header;
	if (!processor_affinity)
		return -EINVAL;

	acpi_table_print_srat_entry(header);

	/* let architecture-dependent part to do it */
	acpi_numa_processor_affinity_init(processor_affinity);

	return 0;
}

static int __init
acpi_parse_memory_affinity(acpi_table_entry_header * header,
			   const unsigned long end)
{
	struct acpi_table_memory_affinity *memory_affinity;

	memory_affinity = (struct acpi_table_memory_affinity *)header;
	if (!memory_affinity)
		return -EINVAL;

	acpi_table_print_srat_entry(header);

	/* let architecture-dependent part to do it */
	acpi_numa_memory_affinity_init(memory_affinity);

	return 0;
}

static int __init acpi_parse_srat(unsigned long phys_addr, unsigned long size)
{
	struct acpi_table_srat *srat;

	if (!phys_addr || !size)
		return -EINVAL;

	srat = (struct acpi_table_srat *)__va(phys_addr);

	return 0;
}

int __init
acpi_table_parse_srat(enum acpi_srat_entry_id id,
		      acpi_madt_entry_handler handler, unsigned int max_entries)
{
	return acpi_table_parse_madt_family(ACPI_SRAT,
					    sizeof(struct acpi_table_srat), id,
					    handler, max_entries);
}

int __init acpi_numa_init(void)
{
	int result;

	/* SRAT: Static Resource Affinity Table */
	result = acpi_table_parse(ACPI_SRAT, acpi_parse_srat);

	if (result > 0) {
		result = acpi_table_parse_srat(ACPI_SRAT_PROCESSOR_AFFINITY,
					       acpi_parse_processor_affinity,
					       NR_CPUS);
		result = acpi_table_parse_srat(ACPI_SRAT_MEMORY_AFFINITY, acpi_parse_memory_affinity, NR_NODE_MEMBLKS);	// IA64 specific
	}

	/* SLIT: System Locality Information Table */
	result = acpi_table_parse(ACPI_SLIT, acpi_parse_slit);

	acpi_numa_arch_fixup();
	return 0;
}

int acpi_get_pxm(acpi_handle h)
{
	unsigned long pxm;
	acpi_status status;
	acpi_handle handle;
	acpi_handle phandle = h;

	do {
		handle = phandle;
		status = acpi_evaluate_integer(handle, "_PXM", NULL, &pxm);
		if (ACPI_SUCCESS(status))
			return (int)pxm;
		status = acpi_get_parent(handle, &phandle);
	} while (ACPI_SUCCESS(status));
	return -1;
}
EXPORT_SYMBOL(acpi_get_pxm);

int acpi_get_node(acpi_handle *handle)
{
	int pxm, node = -1;

	pxm = acpi_get_pxm(handle);
	if (pxm >= 0)
		node = acpi_map_pxm_to_node(pxm);

	return node;
}
EXPORT_SYMBOL(acpi_get_node);
