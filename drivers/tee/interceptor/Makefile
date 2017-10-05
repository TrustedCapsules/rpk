CFG_TEE_CORE_CORE_TARGET := armv7

#########################################################################
# Set Internal Variables                                                #
# May be modified to match your setup                                   #
#########################################################################
CFG_TEE_DRV_DEBUGFS?=0
CFG_TEE_CORE_LOG_LEVEL?=2
CFG_TEE_TA_LOG_LEVEL?=2

ccflags-y+=-O0 -Wno-unused-function
ccflags-y+=-I$(PWD)/../optee_app/common

ccflags-y+=-DCFG_TEE_DRV_DEBUGFS=${CFG_TEE_DRV_DEBUGFS}
ccflags-y+=-DCFG_TEE_CORE_LOG_LEVEL=${CFG_TEE_CORE_LOG_LEVEL}
ccflags-y+=-DCFG_TEE_TA_LOG_LEVEL=${CFG_TEE_TA_LOG_LEVEL}
ifdef HIKEY
ccflags-y+=-DHIKEY=${HIKEY}
endif

obj-m += interceptor.o
interceptor-objs := \
	tee_kernel_api.o \
	tester.o \
	util.o \

$(info $$PWD is [${PWD}])
#$(info $$CC is [${CC}])

clean-interceptor:
	rm -f *.o
	rm -f *.ko
	rm -f *.mod.c
