#include <linux/string.h>
#include "tee_kernel_api.h"
#include "../tee_private.h"
#include <linux/tee_drv.h>

static uint32_t tee_pre_process_tempref(struct tee_context *ctx, uint32_t param_type,
	TEE_TempMemoryReference *tmpref, struct tee_param *param, struct tee_shm *shm) 
{
	uint32_t res;

	switch (param_type) {
		case TEE_MEMREF_TEMP_INPUT:
			param->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
			shm->flags = TEE_MEM_INPUT;
			break;
		case TEE_MEMREF_TEMP_OUTPUT:
			param->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
			shm->flags = TEE_MEM_OUTPUT;
			break;
		case TEE_MEMREF_TEMP_INOUT:
			param->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT;
			shm->flags = TEE_MEM_INPUT | TEE_MEM_OUTPUT;
			break;
		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}

	shm->size = tmpref->size;

	res = TEE_AllocateSharedMemory(ctx, shm, tmpref->size);

	if (res != TEE_SUCCESS) {
		return res;
	}

	memcpy(shm->kaddr, tmpref->buffer, tmpref->size);
	param->u.memref.size = tmpref->size;
	param->u.memref.shm = shm;

	return TEE_SUCCESS;
}

static uint32_t tee_operation_to_param(struct tee_context *ctx,
			TEE_Operation *operation,
			struct tee_param *params,
			struct tee_shm *shms) {

	uint32_t res;
	size_t n;

	memset(shms, 0, sizeof(struct tee_shm) * TEE_CONFIG_PAYLOAD_REF_COUNT);

	if (!operation) { // No operation given
		memset(params, 0, sizeof(struct tee_param) * TEE_CONFIG_PAYLOAD_REF_COUNT);
		return TEE_SUCCESS;
	}

	for (n = 0; n < TEE_CONFIG_PAYLOAD_REF_COUNT; n++) {
		uint32_t param_type;

		param_type = TEE_PARAM_TYPE_GET(operation->paramTypes, n);
		switch(param_type) {
			case TEE_NONE:
				params[n].attr = param_type;
				break;
			case TEE_VALUE_INPUT:
			case TEE_VALUE_OUTPUT:
			case TEE_VALUE_INOUT:
				params[n].attr = param_type;
				params[n].u.value.a = operation->params[n].value.a;
				params[n].u.value.b = operation->params[n].value.b;
				break;
			case TEE_MEMREF_TEMP_INPUT:
			case TEE_MEMREF_TEMP_OUTPUT:
			case TEE_MEMREF_TEMP_INOUT:
				res = tee_pre_process_tempref(ctx, param_type, &operation->params[n].tmpref,
					params + n, shms + n);
				if (res != TEE_SUCCESS)
					return res;
				break;
			default:
				return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	return TEE_SUCCESS;
}

static void tee_post_process_tmpref(uint32_t param_type,
			TEE_TempMemoryReference *tmpref,
			struct tee_param *param,
			struct tee_shm *shm)
{
	if (param_type != TEE_MEMREF_TEMP_INPUT) {
		if (param->u.memref.size <= tmpref->size && tmpref->buffer)
			memcpy(tmpref->buffer, shm->kaddr,
			       param->u.memref.size);

		tmpref->size = param->u.memref.size;
	}
}

static void tee_params_to_operation(TEE_Operation *operation, struct tee_param
	*params, struct tee_shm *shms) {
	size_t n;

	if (!operation) { // No operation given
		return;
	}

	for (n = 0; n < TEE_CONFIG_PAYLOAD_REF_COUNT; n++) {
		uint32_t param_type;

		param_type = TEE_PARAM_TYPE_GET(operation->paramTypes, n);
		switch(param_type) {
			case TEE_VALUE_INPUT:
				break;
			case TEE_VALUE_OUTPUT:
			case TEE_VALUE_INOUT:
				operation->params[n].value.a = params[n].u.value.a;
				operation->params[n].value.b = params[n].u.value.b;
				break;
			case TEE_MEMREF_TEMP_INPUT:
			case TEE_MEMREF_TEMP_OUTPUT:
			case TEE_MEMREF_TEMP_INOUT:
				tee_post_process_tmpref(param_type, &operation->params[n].tmpref, 
					params + n, shms + n);
				break;
			default:
				break;
		}
	}
}

static void tee_free_temp_refs(TEE_Operation *operation,
			struct tee_shm *shms)
{
	size_t n;

	if (!operation)
		return;

	for (n = 0; n < TEE_CONFIG_PAYLOAD_REF_COUNT; n++) {
		switch (TEE_PARAM_TYPE_GET(operation->paramTypes, n)) {
		case TEE_MEMREF_TEMP_INPUT:
		case TEE_MEMREF_TEMP_OUTPUT:
		case TEE_MEMREF_TEMP_INOUT:
			TEE_ReleaseSharedMemory(shms + n);
			break;
		default:
			break;
		}
	}
}

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

int TEE_AllocateSharedMemory(struct tee_context *context, struct tee_shm *shm, size_t size) {
 //  struct tee_shm *shm;
	// int fd;
	// int id;
	// uint32_t flags;
	// size_t alloc_size;

  shm = tee_shm_alloc(context, size, TEE_SHM_MAPPED | TEE_SHM_DMA_BUF);
  tee_shm_get_fd(shm); // needed to increase reference count.

	// if (fd < 0) {
	// 	return 0xFFFF000C;
	// }

 //  id = shm->id;
 //  flags = shm->flags;
 //  alloc_size = shm->size;

 //  sharedMem->buffer = mmap(NULL, sharedMem->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
 //  close(fd);

	// if (sharedMem->buffer == (void *)(-1)) {
	// 	sharedMem->id = -1;
	// 	return 0xFFFF000C;
	// }
	// sharedMem->shadow_buffer = NULL;
	// sharedMem->alloced_size = sharedMem->size;
	// sharedMem->registered_fd = -1;
  return 0;
}

void TEE_ReleaseSharedMemory(struct tee_shm *shm) {
	tee_shm_free(shm);
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
int TEE_InvokeCommand(struct tee_context *ctx, uint32_t session, uint32_t
	cmd_id, TEE_Operation *operation, uint32_t *returnOrigin) {
	int rc, res, eorig;
	uint64_t buf[(sizeof(struct tee_ioctl_invoke_arg) +
			TEE_CONFIG_PAYLOAD_REF_COUNT *
				sizeof(struct tee_param)) /
			sizeof(uint64_t)] = { 0 };
	struct tee_shm shms[TEE_CONFIG_PAYLOAD_REF_COUNT];
	struct tee_ioctl_invoke_arg *arg; // What is passed to tee_client_invoke
	struct tee_param *params; // What is passed to tee_client_invoke

	// Setup arg
	arg = (struct tee_ioctl_invoke_arg *)buf;
	arg->num_params = TEE_CONFIG_PAYLOAD_REF_COUNT;
	params = (struct tee_param *)(arg + 1);

	arg->session = session;
	arg->func = cmd_id;

	operation->session = session;

	// Convert operation to param
	res = tee_operation_to_param(ctx, operation, params, shms);
	if (res != TEE_SUCCESS) {
		eorig = TEE_ORIGIN_API;
		goto out_free_temp_refs;
	}

	// Call client invoke
	rc = tee_client_invoke_func(ctx, arg, params);

	// Check for error
	if (rc) {
		printk(KERN_ERR "tee_client_invoke_func failed");
		eorig = TEE_ORIGIN_TEE;
		res = rc;
		goto out_free_temp_refs;
	}

	// Set appropriate output values
	res = arg->ret;
	eorig = arg->ret_origin;
	tee_params_to_operation(operation, params, shms);

out_free_temp_refs:
	tee_free_temp_refs(operation, shms);
out:
	if (returnOrigin)
		*returnOrigin = eorig;
	// return
	return rc;
}