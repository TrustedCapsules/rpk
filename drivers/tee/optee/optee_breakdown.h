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

/*
struct benchmarking_driver driver_ts[6];
volatile unsigned long long cnt_b1 = 0, cnt_b2 = 0; // might need volatile
volatile int curr_ts = 5;
EXPORT_SYMBOL(curr_ts);
EXPORT_SYMBOL(cnt_b1);
EXPORT_SYMBOL(cnt_b2);
EXPORT_SYMBOL(driver_ts);
*/
#endif /*OPTEE_BREAKDOWN_H*/
