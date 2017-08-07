$(info $$CONFIG_HIKEY is [${CONFIG_HIKEY}])

obj-$(CONFIG_TEE) += tee.o
tee-objs += tee_core.o
tee-objs += tee_shm.o
tee-objs += tee_shm_pool.o
obj-$(CONFIG_OPTEE) += optee/
# Change to be CONFIG_INTERCEPTOR
obj-$(CONFIG_OPTEE) += interceptor/
