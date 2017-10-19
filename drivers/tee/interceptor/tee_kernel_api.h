#ifndef TEE_KERNEL_API_H
#define TEE_KERNEL_API_H

#include <linux/limits.h>
#include <linux/tee_drv.h>

#define TEE_LOGIN_PUBLIC    0x00000000
#define TEE_CONFIG_PAYLOAD_REF_COUNT 4

#define TEE_NONE                   0x00000000
#define TEE_VALUE_INPUT            0x00000001
#define TEE_VALUE_OUTPUT           0x00000002
#define TEE_VALUE_INOUT            0x00000003
#define TEE_MEMREF_TEMP_INPUT      0x00000005
#define TEE_MEMREF_TEMP_OUTPUT     0x00000006
#define TEE_MEMREF_TEMP_INOUT      0x00000007

#define TEE_MEM_INPUT   0x00000001
#define TEE_MEM_OUTPUT  0x00000002

#define TEE_PARAM_TYPE_GET(p, i) (((p) >> (i * 4)) & 0xF)

#define TEE_SUCCESS                0x00000000
#define TEE_ERROR_BAD_PARAMETERS   0xFFFF0006

#define TEE_ORIGIN_API          0x00000001
#define TEE_ORIGIN_COMMS        0x00000002
#define TEE_ORIGIN_TEE          0x00000003
#define TEE_ORIGIN_TRUSTED_APP  0x00000004

typedef struct {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t  clockSeqAndNode[8];
} TEE_UUID;

typedef struct {
	void *buffer;
	size_t size;
} TEE_TempMemoryReference;

typedef struct {
	uint32_t a;
	uint32_t b;
} TEE_Value;

typedef union {
	TEE_TempMemoryReference tmpref;
	TEE_Value value;
} TEE_Parameter;

typedef struct {
	uint32_t started;
	uint32_t paramTypes;
	TEE_Parameter params[TEE_CONFIG_PAYLOAD_REF_COUNT];
	uint32_t session;
} TEE_Operation;

/*
 * TEE_AllocateSharedMemory() - Allocated shared memory for TEE.
 *
 * Should operate the exact same as the client version (TEEC*), but can be
 * called from the kernel driver.
 */
int TEE_AllocateSharedMemory(struct tee_context *context, struct tee_shm *shm, size_t size);

/*
 * TEE_ReleaseSharedMemory() - Frees shared memory for TEE.
 *
 * Should operate the exact same as the client version (TEEC*), but can be
 * called from the kernel driver.
 */
void TEE_ReleaseSharedMemory(struct tee_shm *shm);

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
int TEE_InvokeCommand(struct tee_context *ctx, uint32_t session, uint32_t
	commandID, TEE_Operation *operation, uint32_t *returnOrigin);
#endif
