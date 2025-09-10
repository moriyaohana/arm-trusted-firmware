#include <common/runtime_svc.h>
#include <lib/smccc.h>
#include <common/debug.h>

#define SHA_SMC_ID 0x0001
#define SHA_SMC_CALL_ID                                         \
	((SMC_TYPE_FAST << FUNCID_TYPE_SHIFT) |                                \
	 ((SMC_64) << FUNCID_CC_SHIFT) | (OEN_SHA_START << FUNCID_OEN_SHIFT) | \
	 ((SHA_SMC_ID) & FUNCID_NUM_MASK))

static int sha_svc_setup(void)
{
    NOTICE("Sha SMC FID: %lu\n", SHA_SMC_CALL_ID);

    return 0;
}

/*
 * This function handles Secure SHA256.
 */
static uintptr_t sha_svc_handler(unsigned int smc_fid,
            u_register_t x1,
			u_register_t x2,
			u_register_t x3,
			u_register_t x4,
			void *cookie,
			void *handle,
			u_register_t flags)
{
    NOTICE("sha svc handler call\n");
    SMC_RET1(handle, SMC_UNK);
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
