#include <linux/string.h>
#include "tee_kernel_api.h"
#include "../tee_private.h"
#include <linux/tee_drv.h>
#include <linux/err.h>

static uint32_t tee_pre_process_tempref(struct tee_context *ctx, uint32_t param_type,
	TEE_TempMemoryReference *tmpref, struct tee_param *param, struct tee_shm **shm) 
{
	uint32_t res = TEE_SUCCESS;

	res = TEE_AllocateSharedMemory(ctx, tmpref->size, shm);

	if (res != TEE_SUCCESS) {
        printk("Alloc not successful\n");
		return res;
	}

	switch (param_type) {
		case TEE_MEMREF_TEMP_INPUT:
			param->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
			break;
		case TEE_MEMREF_TEMP_OUTPUT:
			param->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
			break;
		case TEE_MEMREF_TEMP_INOUT:
			param->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT;
			break;
		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}

	// printk("[TEE_PRE_PROCESS_TEMPREF] shm obj: %p, shm->teedev: %p, shm->kaddr:%p, "
	// 	"shm->teedev->mutex: %p\n", *shm, (*shm)->teedev, (*shm)->kaddr,
	// 	&(*shm)->teedev->mutex);


	// printk("[TEE_PRE_PROCESS_TEMPREF] Attempting to memcpy %s at %p to %p\n", 
	// 	(char*) tmpref->buffer, tmpref->buffer, (*shm)->kaddr);
	memcpy((*shm)->kaddr, tmpref->buffer, tmpref->size);
	// printk("[TEE_PRE_PROCESS_TEMPREF] memcpy %s at %p to %p complete.\n", 
	// 	(char*) tmpref->buffer, tmpref->buffer, (*shm)->kaddr);
	param->u.memref.size = tmpref->size;
	param->u.memref.shm = *shm;

	return res;
}

static uint32_t tee_operation_to_param(struct tee_context *ctx,
			TEE_Operation *operation,
			struct tee_param *params,
			struct tee_shm **shms) {

	uint32_t res;
	size_t n;

	memset(shms, 0, sizeof(*shms) * TEE_CONFIG_PAYLOAD_REF_COUNT);

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
				// printk("Temp in/out: %lu, shms: %p\n", n, shms);
				res = tee_pre_process_tempref(ctx, param_type, &operation->params[n].tmpref,
					params + n, &shms[n]);
				// printk("[TEE_OPERATION_TO_PARAM] shm obj: %p, shm->teedev: %p, "
				// 	"shm->kaddr:%p, n: %lu, shms: %p\n", shms[n], shms[n]->teedev, 
					// shms[n]->kaddr, n, shms);
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
	*params, struct tee_shm **shms) {
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
					params + n, shms[n]);
				break;
			default:
				break;
		}
	}
}

static void tee_free_temp_refs(TEE_Operation *operation,
			struct tee_shm **shms)
{
	size_t n;

	if (!operation)
		return;

    // printk("shms addr: %p\n", shms);

	for (n = 0; n < TEE_CONFIG_PAYLOAD_REF_COUNT; n++) {
		// printk("[TEE_FREE_TEMP_REFS] checking param %lu\n", n);
		switch (TEE_PARAM_TYPE_GET(operation->paramTypes, n)) {
		case TEE_MEMREF_TEMP_INPUT:
		case TEE_MEMREF_TEMP_OUTPUT:
		case TEE_MEMREF_TEMP_INOUT:
			// printk("[TEE_FREE_TEMP_REFS] shms[n]: %p, n: %lu, shms: %p, *shms: %p "
			// 	" *shms + n: %p\n", shms[n], n, shms, *shms, *(shms + n));
			if (shms[n] != NULL) {
				// printk("[TEE_FREE_TEMP_REFS] shm[n]->teedev: %p, shm[n]->kaddr:%p, \n", 
				// 	shms[n]->teedev, shms[n]->kaddr); 
				TEE_ReleaseSharedMemory(shms[n]);
			}
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

int TEE_AllocateSharedMemory(struct tee_context *context, size_t
	size, struct tee_shm **shm) {
	int res;
  void *vaddr;

  // printk("[TEE_AllocateSharedMemory] attempting to allocate %lu bytes", size);

  *shm = tee_shm_alloc(context, size, TEE_SHM_MAPPED);

  // printk("[TEE_AllocateSharedMemory] received address %p, shm->flags %x\n",
  // 	*shm, *shm != NULL ? (*shm)->flags : 0);

  if (IS_ERR(*shm)) {
  	printk("Error with allocating shm: %lu\n", PTR_ERR(*shm));
  	res = PTR_ERR(*shm);
  	*shm = NULL;
  	return res;
  }

  vaddr = tee_shm_get_va(*shm, 0);

  if (IS_ERR(vaddr)) {
  	printk("Error with allocating vaddr: %lu\n", PTR_ERR(vaddr));
  	return PTR_ERR(vaddr);
  } 

  // printk("[TEE_AllocateSharedMemory] shm obj: %p, shm->teedev: %p, shm->kaddr:%p, "
  // 	"shm->teedev->mutex: %p\n", *shm, (*shm)->teedev, (*shm)->kaddr,
  	// &(*shm)->teedev->mutex);

  return TEE_SUCCESS;
}

void TEE_ReleaseSharedMemory(struct tee_shm *shm) {
// printk("[TEE_ReleaseSharedMemory] shm obj: %p, shm->teedev: %p, shm->kaddr:%p, "
// 	"shm->teedev->mutex: %p, shm->flags: %x\n", shm, shm->teedev, shm->kaddr,
// 	&shm->teedev->mutex, shm->flags);
    tee_shm_free(shm);
}


int TEE_CloseSession(struct tee_context *ctx, uint32_t session) {
  return tee_client_close_session(ctx, session);
}

int TEE_InvokeCommand(struct tee_context *ctx, uint32_t session, uint32_t
	cmd_id, TEE_Operation *operation, uint32_t *returnOrigin) {
	int rc, res, eorig;
	uint64_t buf[(sizeof(struct tee_ioctl_invoke_arg) +
			TEE_CONFIG_PAYLOAD_REF_COUNT *
				sizeof(struct tee_param)) /
			sizeof(uint64_t)] = { 0 };
	struct tee_shm *shms[TEE_CONFIG_PAYLOAD_REF_COUNT];
	struct tee_ioctl_invoke_arg *arg; // What is passed to tee_client_invoke
	struct tee_param *params; // What is passed to tee_client_invoke

	if (!ctx || !session) {
		eorig = TEE_ORIGIN_API;
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	// Setup arg
	arg = (struct tee_ioctl_invoke_arg *)buf;
	arg->num_params = TEE_CONFIG_PAYLOAD_REF_COUNT;
	params = (struct tee_param *)(arg + 1);

	arg->session = session;
	arg->func = cmd_id;

	operation->session = session;

	// printk("TEE_InvokeCommand with session: %u, cmd_id: %u.\n", session, cmd_id);

	// Convert operation to param
	res = tee_operation_to_param(ctx, operation, params, shms);
	if (res != TEE_SUCCESS) {
		// printk("tee_operation_to_param error %d\n", res);
		eorig = TEE_ORIGIN_API;
		// printk("going to out_free_temp_refs\n");
		goto out_free_temp_refs;
	}

	// Call client invoke
	rc = tee_client_invoke_func(ctx, arg, params);
	// printk("tee_client_invoke_func returned %d\n", rc);
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
	// printk("[TEE_InvokeCommand] returning %d\n", rc);
	return rc;
}
