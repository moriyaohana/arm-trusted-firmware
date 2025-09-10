#include <common/runtime_svc.h>
#include <lib/smccc.h>
#include <common/debug.h>

static int sha_svc_setup(void)
{
    NOTICE("sha svc setup call\n");

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
