#include <linux/string.h>
#include "tee_kernel_api.h"
#include <linux/tee_drv.h>
#include <unistd.h>


static void uuid_to_octets(uint8_t d[TEE_IOCTL_UUID_LEN], const TEE_UUID *s) {
	d[0] = s->timeLow >> 24; 
	d[1] = s->timeLow >> 16; 
	d[2] = s->timeLow >> 8; 
	d[3] = s->timeLow; 
	d[4] = s->timeMid >> 8;
	d[5] = s->timeMid;
	d[6] = s->timeHiAndVersion >> 8;
	d[7] = s->timeHiAndVersion; 
	memcpy(d + 8, s->clockSeqAndNode, sizeof(s->clockSeqAndNode));
}

int TEE_OpenSession(struct tee_context *context, uint32_t *session, const TEE_UUID
	*destination, uint32_t connection_method, struct tee_param *params, uint32_t
	*ret_origin) {

    // Message passing variables
    struct tee_ioctl_open_session_arg arg;
    int rc;

	// Open session args
    memset(&arg, 0, sizeof(arg));

    uuid_to_octets(arg.uuid, destination);
    arg.clnt_login = connection_method;

    rc = tee_client_open_session(context, &arg, NULL);

    // Capsule open failed
    if (arg.ret) {
        rc = -EINVAL;
    } else {
    	*session = arg.session;
    }

    *ret_origin = arg.ret_origin;

    return rc;
}

// MEDIUM
/* int TEE_AllocateSharedMemory(tee_context *context, TEE_SharedMemory *sharedMem) {
	// 1. Create TEE_SharedMemory object (shm_obj) --> caller does this & passes
	//    pointer
	// 2. Create tee_shm object (shm)
	// 3. Get file descriptor and id from tee_shm_alloc: shm = tee_shm_alloc(ctx,
	//    size, TEE_SHM_MAPPED | TEE_SHM_DMA_BUF); fd = tee_shm_get_fd(shm);
	// 4. id = shm->id, flags = shm->flags, alloc_size = shm->size (flags are
	//    unused)
	// 5. shm_obj->buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
	//    fd, 0);
	// 6. Close fd
	// 7. Error check
	// 8. Set optional vars to default

	// NOTES: see linux/drivers/tee/tee_core.c:132 for use of tee_shm_alloc and 
	//        see optee_client/libteec/src/tee_client_api.c:687 for client API call
	//        this is modeled after
}
*/

int TEE_AllocateSharedMemory(struct tee_context *context, TEE_SharedMemory *sharedMem) {
  struct tee_shm *shm;
	int fd;
	int id;
	uint32_t flags;
	size_t alloc_size;

  shm = tee_shm_alloc(context, sharedMem->size, TEE_SHM_MAPPED | TEE_SHM_DMA_BUF);
  fd = tee_shm_get_fd(shm);

	if (fd < 0) {
		return 0xFFFF000C;
	}

  id = shm->id;
  flags = shm->flags;
  alloc_size = shm->size;

  sharedMem->buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);

	if (sharedMem->buffer == (void *)(-1)) {
		sharedMem->id = -1;
		return 0xFFFF000C;
	}
	sharedMem->shadow_buffer = NULL;
	sharedMem->alloced_size = s;
	sharedMem->registered_fd = -1;
  return 0;
}

// EASIEST
/* int TEE_CloseSession(tee_context *ctx, uint32_t session){
	// TODO: James start here
	// Literally just call optee_close_session(ctx, session); --> might not need
	// wrapper
}
*/

int TEE_CloseSession(struct tee_context *ctx, uint32_t session) {
  return tee_client_close_session(ctx, session);
}

// HARDEST
	// 1. Setup variables, must create an populate the tee_ioctl_invoke_arg
	//    correctly (specifically, the num_params, func, session, and cancel_id)
	//    Mainly look at optee_client/libteec/src/tee_client_api.c:536 for how to
	//    do this. It will not be exact (the teec_pre_process_operation shows how it
	//    breaks a TEEC_Operation into tee_params). Will need to call
	//    TEE_AllocateSharedMemory to get the buffer and stuff. The main problem
	//    is tmpmemref.
	//
	// NOTE: might actually need to copy the TEEC_Operation over and the methods
	//       used to convert it.  
/* int TEE_InvokeCommand(uint32_t session, uint32_t commandID, tee_param *param, uint32_t *returnOrigin);
	uint64_t buf[(sizeof(struct tee_ioctl_invoke_arg) + 4 * sizeof(struct
				 tee_ioctl_param)) / sizeof(uint64_t)] = {0};
	struct tee_ioctl_buf_data buf_data;
	struct tee_ioctl_invoke_arg *arg; // What is passed to tee_client_invoke
	struct tee_ioctl_param *params; // What is passed to tee_client_invoke
	uint32_t eorig;
	TEE_SharedMemory shm[4];
	int rc;

	arg = (struct tee_ioctl_invoke_arg*) buf;
	arg->num_params = 4; // TEE_CONFIG_PAYLOAD_REF_COUNT
	params = (struct tee_ioctl_param *)(arg + 1);

	arg->session = session;
	arg->func = commandID;

	// Process the param. 
*/
