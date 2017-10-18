#ifndef TEE_KERNEL_API_H
#define TEE_KERNEL_API_H

#include <linux/limits.h>
#include <linux/tee_drv.h>

#define TEE_LOGIN_PUBLIC    0x00000000

typedef struct {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t  clockSeqAndNode[8];
} TEE_UUID;

typedef struct {
	void *buffer;
	size_t size;
	uint32_t flags;
	/* Implementation defined */
	int id;
	size_t alloced_size;
	void *shadow_buffer;
	int registered_fd;
} TEE_SharedMemory;

/*
 * TEE_AllocateSharedMemory() - Allocated shared memory for TEE.
 *
 * Should operate the exact same as the client version (TEEC*), but can be
 * called from the kernel driver.
 */
int TEE_AllocateSharedMemory(struct tee_context *context, TEE_SharedMemory *sharedMem);

/*
 * TEE_OpenSession() - Open Session for TEE.
 *
 * Should operate the exact same as the client version (TEEC*), but can be
 * called from the kernel driver.
 */
int TEE_OpenSession(struct tee_context *context, uint32_t *session, const TEE_UUID
	*destination, uint32_t connection_method, struct tee_param *params, uint32_t *returnOrigin);

/*
 * TEE_CloseSession() - Close session for TEE.
 *
 * Should operate the exact same as the client version (TEEC*), but can be
 * called from the kernel driver.
 */
int TEE_CloseSession(struct tee_context *ctx, uint32_t session);

/*
 * TEE_InvokeCommand() - Invoke command for TEE.
 *
 * Should operate the exact same as the client version (TEEC*), but can be
 * called from the kernel driver.
 */
// int TEE_InvokeCommand(uint32_t session, uint32_t commandID, tee_param *params,
// 	uint32_t *returnOrigin);
#endif
