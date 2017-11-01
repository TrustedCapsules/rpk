/*
 * Copyright (c) 2015, Linaro Limited
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef OPTEE_BREAKDOWN_H
#define OPTEE_BREAKDOWN_H

#include <linux/tee_drv.h>
#include <linux/types.h>

struct benchmarking_driver {
	unsigned long long  module_op;
	unsigned long long  rpc_peripheral_count;
	unsigned long long  rpc_shm_count;
	unsigned long long  rpc_cmd_count;
	unsigned long long  rpc_fs_count;
	unsigned long long  rpc_net_count;
	unsigned long long  rpc_other_count; /*ta, irq, suspend, wait_queue*/
};

static inline unsigned long long read_cntpct(void) {
	unsigned long long ts;

// #ifdef HIKEY
	asm volatile( "mrs %0, cntpct_el0" : "=r" (ts) );
// #else
// 	asm volatile( "mrcc p15, 0, %Q0, %R0, c14" : "=r" (ts) );
// #endif
	return ts;
}

#endif /*OPTEE_BREAKDOWN_H*/
