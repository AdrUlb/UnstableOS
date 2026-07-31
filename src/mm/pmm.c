#ifndef USE_LEGACY_PFA

#include "mm/kernel_memory.h"

#include <stdbool.h>
#include <string.h>

#include "kernel.h"
#include "multiboot.h"

// Maximum allocation order: 2^10 = 1024 pages = 4 MiB
#define PMM_ORDER_MAX 10

// Sentinel value, indicates that this is a tail page
// The refcount is instead the page number of the allocation's head page
#define PMM_ORDER_TAIL (PMM_ORDER_MAX + 1)

// Sentinel value, indicates that this page is free
// The refcount is instead the page number of the next free page in the free list
#define PMM_ORDER_FREE (PMM_ORDER_MAX + 2)

typedef struct
{
	// The reference count of this page
	// or the page number of the allocation's head page if order == PMM_ORDER_TAIL
	// or the page number of the next free page if order == PMM_ORDER_FREE
	uint32_t refcount : 24;
	uint32_t order : 8;
} pmm_page_info_t;

#define PAGE_ALIGN_UP(address) ((address + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_DOWN(address) (address & ~(PAGE_SIZE - 1))

// This is where the page info structs live in memory
#define PAGES_START 0x07000000
#define PAGES_END 0x08000000

typedef struct
{
	size_t start;
	size_t end;
} pre_vmm_range_t;

// This structure takes up exactly one page and is freed into the PMM after the VMM is up and running
#define PRE_VMM_RANGES_MAX ((PAGE_SIZE - sizeof(size_t)) / sizeof(pre_vmm_range_t))

static struct __attribute__((packed, aligned(PAGE_SIZE)))
{
	pre_vmm_range_t ranges[PRE_VMM_RANGES_MAX];
	size_t ranges_count;
} pre_vmm_info;

// We can safely use 0 as the end-of-freelist sentinel because page 0 is not allowed to be marked as free
static size_t freelists[PMM_ORDER_MAX + 1] = { 0 };

static pmm_page_info_t* pages = (pmm_page_info_t*)PAGES_START;

static bool early;

static void pre_vmm_insert_range(const size_t start, const size_t end, pre_vmm_range_t* ranges, size_t* ranges_count, const size_t ranges_max)
{
	if (start >= end)
		return;

	size_t i = 0;

	// Find the first range that doesn't end before we start
	// (we touch it, overlap it, or must be inserted before it)
	while (i < *ranges_count && ranges[i].end < start)
		i++;

	// Are we appending to the end *or* NOT merging?
	if (i == *ranges_count || ranges[i].start > end)
	{
		if (*ranges_count >= ranges_max)
			return;

		for (size_t j = *ranges_count; j > i; j--) // Shift all ranges over to make room for the new one
			ranges[j] = ranges[j - 1];

		ranges[i].start = start;
		ranges[i].end = end;
		(*ranges_count)++;
		return;
	}

	// We found a range we overlap with or touch, extend it
	if (start < ranges[i].start)
		ranges[i].start = start;

	if (end > ranges[i].end)
		ranges[i].end = end;

	size_t next = i + 1;

	while (next < *ranges_count && ranges[i].end >= ranges[next].start)
	{
		if (ranges[next].end > ranges[i].end)
			ranges[i].end = ranges[next].end;

		next++;
	}

	const size_t merge_count = next - 1 - i;

	if (merge_count > 0)
	{
		for (size_t j = i + 1; j < *ranges_count - merge_count; j++)
			ranges[j] = ranges[j + merge_count];

		*ranges_count -= merge_count;
	}
}

#define PRE_VMM_RESERVED_RANGES_MAX 32

static void pre_vmm_insert_range_checked(size_t start, const size_t end, const multiboot_info_t* multiboot_info)
{
	pre_vmm_range_t reserved[PRE_VMM_RESERVED_RANGES_MAX]; // Let's hope 32 is enough here >_<
	size_t reserved_count = 0;

	// Add the kernel to the list of ranges to avoid
	pre_vmm_insert_range(
		PAGE_ALIGN_DOWN((uintptr_t)KERNEL_START) / PAGE_SIZE,
		PAGE_ALIGN_UP((uintptr_t)KERNEL_END) / PAGE_SIZE,
		reserved, &reserved_count, PRE_VMM_RESERVED_RANGES_MAX);

	// Protect the multiboot structure itself
	pre_vmm_insert_range(
		PAGE_ALIGN_DOWN((uintptr_t)multiboot_info) / PAGE_SIZE,
		PAGE_ALIGN_UP((uintptr_t)multiboot_info + sizeof(multiboot_info_t)) / PAGE_SIZE,
		reserved, &reserved_count, PRE_VMM_RESERVED_RANGES_MAX);

	// ...and the command line
	if (multiboot_info->flags & MULTIBOOT_INFO_CMDLINE)
	{
		pre_vmm_insert_range(
			PAGE_ALIGN_DOWN((uintptr_t)multiboot_info->cmdline) / PAGE_SIZE,
			PAGE_ALIGN_UP((uintptr_t)multiboot_info->cmdline + strlen((char*)multiboot_info->cmdline) + 1) / PAGE_SIZE,
			reserved, &reserved_count, PRE_VMM_RESERVED_RANGES_MAX);
	}

	// ...and modules
	if (multiboot_info->flags & MULTIBOOT_INFO_MODS)
	{
		const multiboot_module_t* mods = (const multiboot_module_t*)multiboot_info->mods_addr;
		for (size_t i = 0; i < multiboot_info->mods_count; i++)
		{
			pre_vmm_insert_range(
				PAGE_ALIGN_DOWN((uintptr_t)mods[i].mod_start) / PAGE_SIZE,
				PAGE_ALIGN_UP((uintptr_t)mods[i].mod_end) / PAGE_SIZE,
				reserved, &reserved_count, PRE_VMM_RESERVED_RANGES_MAX);

			pre_vmm_insert_range(
				PAGE_ALIGN_DOWN((uintptr_t)mods[i].cmdline) / PAGE_SIZE,
				PAGE_ALIGN_UP((uintptr_t)mods[i].cmdline + strlen((char*)mods[i].cmdline) + 1) / PAGE_SIZE,
				reserved, &reserved_count, PRE_VMM_RESERVED_RANGES_MAX);
		}

		pre_vmm_insert_range(
			PAGE_ALIGN_DOWN((uintptr_t)multiboot_info->mods_addr) / PAGE_SIZE,
			PAGE_ALIGN_UP((uintptr_t)multiboot_info->mods_addr + multiboot_info->mods_count * sizeof(multiboot_module_t)) / PAGE_SIZE,
			reserved, &reserved_count, PRE_VMM_RESERVED_RANGES_MAX);
	}

	// ...and the bootloader name
	if (multiboot_info->flags & MULTIBOOT_INFO_BOOT_LOADER_NAME)
	{
		pre_vmm_insert_range(
			PAGE_ALIGN_DOWN((uintptr_t)multiboot_info->boot_loader_name) / PAGE_SIZE,
			PAGE_ALIGN_UP((uintptr_t)multiboot_info->boot_loader_name + strlen((char*)multiboot_info->boot_loader_name) + 1) / PAGE_SIZE,
			reserved, &reserved_count, PRE_VMM_RESERVED_RANGES_MAX);
	}

	// ...and the drive info
	if (multiboot_info->flags & MULTIBOOT_INFO_DRIVE_INFO)
	{
		pre_vmm_insert_range(
			PAGE_ALIGN_DOWN((uintptr_t)multiboot_info->drives_addr) / PAGE_SIZE,
			PAGE_ALIGN_UP((uintptr_t)multiboot_info->drives_addr + multiboot_info->drives_length) / PAGE_SIZE,
			reserved, &reserved_count, PRE_VMM_RESERVED_RANGES_MAX);
	}

	// ...and the symbol tables
	if (multiboot_info->flags & MULTIBOOT_INFO_ELF_SHDR)
	{
		pre_vmm_insert_range(
			PAGE_ALIGN_DOWN((uintptr_t)multiboot_info->u.elf_sec.addr) / PAGE_SIZE,
			PAGE_ALIGN_UP((uintptr_t)multiboot_info->u.elf_sec.addr + multiboot_info->u.elf_sec.num * multiboot_info->u.elf_sec.size) / PAGE_SIZE,
			reserved, &reserved_count, PRE_VMM_RESERVED_RANGES_MAX);
	}

	for (size_t i = 0; i < reserved_count; i++)
	{
		// Reserved block is entirely behind the range, next.
		if (reserved[i].end <= start)
			continue;

		// Reserved block is entirely in front of the range, done checking!
		if (reserved[i].start >= end)
			break;

		// There is some free memory before the reserved block
		if (reserved[i].start > start)
			pre_vmm_insert_range(start, reserved[i].start, pre_vmm_info.ranges, &pre_vmm_info.ranges_count, PRE_VMM_RANGES_MAX);

		// Move past the block
		if (reserved[i].end > start)
			start = reserved[i].end;
	}

	// Add any remaining space
	if (start < end)
		pre_vmm_insert_range(start, end, pre_vmm_info.ranges, &pre_vmm_info.ranges_count, PRE_VMM_RANGES_MAX);
}

void pmm_init_pre_vmm(const multiboot_info_t* multiboot_info)
{
	early = true;
	pre_vmm_info.ranges_count = 0;

	const volatile multiboot_memory_map_t* entry;

	for (size_t entry_offset = 0; entry_offset < multiboot_info->mmap_length; entry_offset += entry->size + sizeof(entry->size))
	{
		entry = (multiboot_memory_map_t*)(multiboot_info->mmap_addr + entry_offset);

		if (entry->type != MULTIBOOT_MEMORY_AVAILABLE)
			continue;

		// Find page-aligned start (inclusive) and end (exclusive) of this entry
		size_t start_page = PAGE_ALIGN_UP(entry->addr) / PAGE_SIZE;
		size_t end_page = PAGE_ALIGN_DOWN(entry->addr + entry->len) / PAGE_SIZE;

		// This range is entirely outside the 32-bit address range
		if (start_page > UINT32_MAX / PAGE_SIZE + 1)
			continue;

		// This range exceeds the 32-bit address range, limit it to that range
		if (end_page > UINT32_MAX / PAGE_SIZE + 1)
			end_page = UINT32_MAX / PAGE_SIZE + 1;

		if (start_page == 0)
			start_page = 1;

		if (start_page >= end_page) // The range did not contain any whole pages
			continue;

		pre_vmm_insert_range_checked(start_page, end_page, multiboot_info);
	}
}

void pmm_init_post_vmm()
{
	// TODO

	/*
	for (uintptr_t virt = PMM_PAGES_START; virt < PMM_PAGES_END; virt += PAGE_SIZE)
	{
		paging_map_phys_addr(, (void*)virt, PTE_PDE_PAGE_WRITABLE);
	}
	*/
}

static inline __attribute__((always_inline)) size_t pmm_pre_vmm_alloc()
{
	while (true)
	{
		kassert(pre_vmm_info.ranges_count > 0);
		pre_vmm_range_t* range = pre_vmm_info.ranges + (pre_vmm_info.ranges_count - 1);
		if (range->start >= range->end)
		{
			pre_vmm_info.ranges_count--;
			continue;
		}

		return range->start++;
	}
}

size_t pmm_alloc(const size_t order)
{
	if (early)
	{
		kassert(order == 0);
		return pmm_pre_vmm_alloc();
	}

	// TODO
	kassert(false);
}

void pmm_free(const size_t page_num)
{
	//kassert(!early);

	// TODO
}

void pmm_retain(const size_t page_num)
{
	//kassert(!early);

	// TODO
}

size_t pmm_get_usable_page_count()
{
	// TODO: actually return the number of usable pages, claim 16 MiB of usable memory for now
	return 16 * 1024 * 1024 / 4096;
}

size_t pmm_get_free_page_count()
{
	// TODO: actually return the number of usable pages, claim 16 MiB of free memory for now
	return 16 * 1024 * 1024 / 4096;
}

// Satisfy the silly old interface

unsigned long pf_get_free_memory()
{
	return pmm_get_free_page_count() * 4096;
}

void* pfalloc()
{
	return (void*)(pmm_alloc(0) * PAGE_SIZE);
}

void* pfalloc_1M()
{
	return (void*)(pmm_alloc(pmm_size_to_order(1 * 1024 * 1024)) * PAGE_SIZE);
}

void pffree(void* page)
{
	pmm_free((uintptr_t)page / PAGE_SIZE);
}

void pffree_1M(void* block_1M_start)
{
	pmm_free((uintptr_t)block_1M_start / PAGE_SIZE);
}

void* pfalloc_dup_page(void* page)
{
	void* new_frame = pfalloc();
	kassert(new_frame);
	void* mapped_new = paging_map_phys_addr_unspecified(new_frame, PTE_PDE_PAGE_WRITABLE);
	kassert(mapped_new);
	void* mapped_old = paging_map_phys_addr_unspecified(page, PTE_PDE_PAGE_WRITABLE);
	kassert(mapped_old);

	memcpy(mapped_new, mapped_old, PAGE_SIZE);
	paging_unmap_page(mapped_new);
	paging_unmap_page(mapped_old);

	return new_frame;
}

void* pfalloc_ref_inc(void* page)
{
	pmm_retain((uintptr_t)page / PAGE_SIZE);
	return page;
}

#endif
