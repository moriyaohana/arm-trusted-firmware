#include <common/runtime_svc.h>
#include <lib/smccc.h>
#include <lib/xlat_tables/xlat_tables_v2.h>
#include <common/debug.h>
#include <drivers/auth/crypto_mod.h>
#include "sha256.h"

#define SHA_SMC_ID 0x0001
#define SHA_SMC_CALL_ID                                         \
	((SMC_TYPE_FAST << FUNCID_TYPE_SHIFT) |                                \
	 ((SMC_64) << FUNCID_CC_SHIFT) | (OEN_SHA_START << FUNCID_OEN_SHIFT) | \
	 ((SHA_SMC_ID) & FUNCID_NUM_MASK))

#define PAGE_MASK   (~(PAGE_SIZE - 1UL))

#define ALIGN_UP(addr)   (((addr) + PAGE_SIZE - 1UL) & PAGE_MASK)

static inline uintptr_t align_down_to_page(uintptr_t addr)
{
    return addr & PAGE_MASK;
}

static inline uintptr_t page_offset(uintptr_t addr)
{
    return addr & (PAGE_SIZE - 1);
}

static int sha_svc_setup(void)
{
    NOTICE("Sha SMC FID: %lu\n", SHA_SMC_CALL_ID);

    return 0;
}

static int map_nonaligned_va(uintptr_t pa, uintptr_t *va, size_t size, unsigned int attr)
{
	uintptr_t pa_page_base = align_down_to_page(pa);

	uintptr_t va_page_base;
	int res = mmap_add_dynamic_region_alloc_va(pa_page_base, &va_page_base, ALIGN_UP(size + page_offset(pa)), attr);
	
	if (res < 0) {
		return res;
	}

	*va = va_page_base + page_offset(pa);

	return res;
}

/*
 * This function handles Secure SHA256.
 */
static uintptr_t sha_svc_handler(unsigned int smc_fid,
            u_register_t input_address,
			u_register_t input_size,
			u_register_t output_address,
			u_register_t x4,
			void *cookie,
			void *handle,
			u_register_t flags)
{
	NOTICE("sha svc handler call with input buffer: 0x%p\n", (void*)input_address);
	NOTICE("sha svc handler call with output buffer: 0x%p\n", (void*)output_address);

	uintptr_t test_data_mapping;
	int res = map_nonaligned_va(input_address, &test_data_mapping, input_size, MT_RO_DATA | MT_NS);
	if (res != 0) {
		NOTICE("Failed to add dynamic region with error %d\n", res);
		SMC_RET1(handle, SMC_UNK);
	}	

	uintptr_t output_buffer_mapping;
	res = map_nonaligned_va(output_address, &output_buffer_mapping, PAGE_SIZE, MT_RW_DATA | MT_NS);
	if (res != 0) {
		NOTICE("Failed to add dynamic region with error %d\n", res);
		SMC_RET1(handle, SMC_UNK);
	}

	sha256_bytes((void*)test_data_mapping, input_size, (unsigned char *)output_buffer_mapping);
	NOTICE("Computed sha\n");


    SMC_RET1(handle, SMC_OK);
}

/* Define a runtime service descriptor for fast SMC calls */
DECLARE_RT_SVC(
	sha_svc,
	OEN_SHA_START,
	OEN_SHA_END,
	SMC_TYPE_FAST,
	sha_svc_setup,
	sha_svc_handler
);
