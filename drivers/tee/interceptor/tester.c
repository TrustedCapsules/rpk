#include <asm/unistd.h>

#include <linux/init.h>
#include <linux/module.h>
#include <linux/tee_drv.h>
#include <uapi/linux/tee.h>
#include <linux/slab.h>
#include <linux/sched.h> // for current variable
#include <linux/hashtable.h>

// Stuff for syscall finder
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/paravirt.h>
#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <asm/pgtable.h>
#include <capsule.h>

#include "../tee_private.h"
#include "../optee/optee_breakdown.h"
#include "tee_kernel_api.h"

#include "helper.h"
#include "util.h"

/* TEE TrustZone context */
struct tee_context *ctx;

/* Address of system call table */
unsigned long long *sys_call_table = NULL;

/* Function pointers to original sys calls */
func_ptr sys_open_addr, // QEMU
         sys_openat_addr,
         sys_close_addr,
         sys_read_addr,
         sys_pread64_addr,
         sys_write_addr,
         sys_lseek_addr,
         sys_fstat_addr,
         sys_lstat_addr,
         sys_stat_addr,
         sys_newfstatat_addr,
         sys_exit_group_addr;

/* Locks for operations to be atomic.
 *
 * The ability to handle concurrent operations from
 * multiple processes is not well tested and benchmarked.
 * It could be that at some point in the future, it would
 * be a good idea to use RCU (read-copy-update) instead of
 * spin_locks.
 *
 * TODO: check if proc_lock is necessary. If the same process
 * calling syscalls on different files, we only need to lock
 * for the reference count modification.
 */
DEFINE_MUTEX(sess_lock);
DEFINE_SPINLOCK(proc_lock);

/* Accessed List: procid -> abs file names
 *
 * This keeps track of a set of trusted capsule files that
 * have been accessed by a process.
 */
DEFINE_HASHTABLE(proc_table, 10);

/* Session List: abs filenames -> TEE sessions
 *
 * This keeps track of a set of TEE Sessions for each trusted
 * capsule. Theoretically, one new instance of TEE Session
 * should be created on each TEEC_OpenSession(). The OP-TEE
 * Linuxdriver should also handle concurrent calls into TrustZone.
 * That is why we do not have locks for this data structure.
 * However, this again is not well tested for now. 
 */
DEFINE_HASHTABLE(sess_table, 10);

volatile unsigned long long cnt_b1 = 0;
volatile unsigned long long cnt_b2 = 0;
volatile int curr_ts = 5;
struct benchmarking_driver driver_ts[6];


/* RW/RO stuff
 */
pgprot_t ro_clear_mask = __pgprot(PTE_WRITE);
pgprot_t ro_set_mask = __pgprot(PTE_RDONLY);
pgprot_t rw_set_mask = __pgprot(PTE_WRITE);
pgprot_t rw_clear_mask = __pgprot(PTE_RDONLY);

// Our syscalls
asmlinkage int openat(int dirfd, const char *file_name, int flags, int mode) {
    // TEE parameters
    uint32_t        sess;
    TEE_UUID        uuid = CAPSULE_UUID;

    // Breakdown params
    // unsigned long long  cnt_a1, cnt_a2;
    // bool                record = false;

    // Other params
    // sys_close_type      sys_close_ptr = (sys_close_type) sys_close_add;
    // char*               pwd_path = kmalloc(PATH_MAX - strlen(file_name), GFP_KERNEL);
    // char*               abs_file_name;
    // char*               path_ptr;
    int                 pwd_len = 0, abs_len = strlen(file_name) + 1, fd = -1, id = 0, found = 0;
    uint32_t            err_origin;
    // struct session*     curr_session = NULL;
    // struct process*     curr_proc = NULL;
    // struct fd_struct*   curr_fd_struct = NULL;
    // bool                truncate = (flags & O_TRUNC) &&
    //                                (flags & O_RDWR || flags & O_WRONLY);
    // bool                iscap = is_capsule(file_name, &id);

    // TODO: add other variables and check for truncate flag
    //
    // Check to see if there is a truncate flag, this messes with the TC header, so we
    // need to override it.
    // if (is_cap && truncate) {
    //     flags = flags & (~O_TRUNC);
    // }

    // TODO: testing remove when building call
    // if (iscap) {
        curr_ts = 0;
    // }

    sys_openat_type     sys_openat_ptr = (sys_openat_type) sys_openat_addr;
    fd = (*sys_openat_ptr)(dirfd, file_name, flags, mode);
    // For testing we need to only run open session on a test file or it hangs.
    if ( strstr(file_name, "bio.capsule") != NULL) {
        printk("Calling open session\n");

        int res = TEE_OpenSession( ctx, &sess, &uuid, TEE_LOGIN_PUBLIC, 
                                    NULL, &err_origin );
        printk("Open session result: %d\n", res);
        printk("Session id: %d\n", sess);
        printk( "Interceptor open(): %s(%d) %d/%d\n", current->comm, fd, current->tgid, fd );
    }
/*
    // Error check the open
    if (fd < 0) {
        fd = -1;
    }

    if (fd >= 0 && strncmp(_tee_supp_app_name, current->comm,
                           strlen(_tee_supp_app_name)) && is_cap) {
        // Breakdown code (set the operation to open - 0) and set record to true
        curr_ts = 0;
        record = true;

        if (file_name[0] != '/') {
            path_ptr = get_pwd_path(pwd_path, PATH_MAX, &pwd_len);
            if (pwd_len < 0) {
                printk("Interceptor open(): current->comm %s "
                        " pwd path not found\n", current->comm);
                goto open_out;
            }
            abs_len += pwd_len + 1;
        }

        abs_file_name = kmalloc(abs_len, GFP_KERNEL);
        if (pwd_len > 0) {
            memcpy(abs_file_name, path_ptr, pwd_len);
            abs_file_name[pwd_len] = '/';
            pwd_len++;
        }

        strcpy(abs_file_name + pwd_len, file_name);

        // Lock the session table 
        mutex_lock(&sess_lock);

        // Look through the table to see if a session already exists for
        // this capsule
        hash_for_each_possible(sess_table, curr_sess, hash_list, id) {
            if (curr_sess->id == id) {
                kfree(abs_file_name);
                abs_file_name = curr_sess->abs_name;
                found = 1;
                break;
            }
        }

        // No matching session found, create one
        if (found != 1) {
            // Call open session

            cnt_a2 = read_cntpct();
            driver_ts[curr_ts].module_op += cnt_b1 - cnt_a1 +
                                            cnt_a2 - cnt_b2;
            cnt_a1 = read_cntpct();
            cnt_b1 = 0;
            cnt_b2 = 0;

            if (rc) {
                (*sys_close_ptr)(fd); // Close file
                fd = -1;
                printk("Interceptor open(): current->comm %s "
                       "tee_client_open_session failed rc %x\n",
                       current->comm, rc);
                mutex_unlock(&sess_lock);
                goto open_out;
            }

        } else { // Found session
            sess = curr_sess->sess;
        }

        // Make capsule open args
        memset(&arg, 0, sizeof(arg));
        arg.func = CAPSULE_OPEN;
        arg.session = sess;
        arg.num_params = 2;

        params = kmalloc_array(arg->num_params, sizeof(struct tee_param),
                        GFP_KERNEL);
        if (!params) {
            //TEEC_ERROR_OUT_OF_MEMORY
        }

        // Declare shared memory for file name
        file_shm = tee_shm_alloc(&ctx, strlen(abs_file_name), TEE_SHM_MAPPED);
        params[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
        params[0].u.memref.shm = shm;
        params[0].u.memref.size = strlen(abs_file_name);

        params[1].attr = TEE_IOCLT_PARAM_ATTR_TYPE_VALUE_INPUT;
        params[1].u.value.a = current->tgid;
        params[1].u.value.b = fd;
    }
    */
    // TODO: Perform capsule logic

open_out:
    // printk("Interceptor open(): %s(%d) %d\n", current->comm, fd, current->tgid);
    return fd;
}

asmlinkage int open(const char* file_name, int flags, int mode) {
    return openat(AT_FDCWD, file_name, flags, mode);
}

asmlinkage int close(int fd) {
    curr_ts = 1;
    sys_close_type  sys_close_ptr = (sys_close_type)sys_close_addr;

    // TODO: perform capsule logic

close_out:
    // printk("Interceptor close(): %s(%d) %d\n", current->comm, fd, current->tgid);
    return (*sys_close_ptr)(fd);
}


asmlinkage int lstat(const char *pathname, struct stat *buf) {
	int id;
	sys_lstat_type sys_lstat_ptr = (sys_lstat_type) sys_lstat_addr;
	int ret = (*sys_lstat_ptr)( pathname, buf );

	//printk( "Interceptor lstat():\n" );
  	if( strncmp( _tee_supp_app_name, current->comm, strlen(_tee_supp_app_name) ) ) {
		if( S_ISREG( buf->st_mode ) ) {
			printk( "Interceptor stat(): \n" );
  			if( is_capsule( pathname, &id ) ){
				printk( "Interceptor stat(): trusted capsule 0x%08x\n", id );
			}
		}
	}
    return ret;
}

asmlinkage int stat(const char *pathname, struct stat *buf) {
	int id;
	sys_stat_type sys_stat_ptr = (sys_stat_type) sys_stat_addr;
	int ret = (*sys_stat_ptr)( pathname, buf );

	//printk( "Interceptor stat():\n" );
  	if( strncmp( _tee_supp_app_name, current->comm, strlen(_tee_supp_app_name) ) ) {
		if( S_ISREG( buf->st_mode ) ) {
			printk( "Interceptor stat():\n" );
  			if( is_capsule( pathname, &id ) ){
				printk( "Interceptor stat(): trusted capsule 0x%08x\n", id );
			}
		}
	}
    return ret;
}

asmlinkage int newfstatat(int dirfd, const char *pathname, struct stat *buf,
                          int flags) {
	sys_newfstatat_type sys_newfstatat_ptr = (sys_newfstatat_type) sys_newfstatat_addr;
	//printk( "Intercepted this newfstatat call\n" );
	return (*sys_newfstatat_ptr)(dirfd, pathname, buf, flags);
}

asmlinkage int fstat(int fd, struct stat *buf) {
    sys_fstat_type  sys_fstat_ptr = (sys_fstat_type) sys_fstat_addr;
    int ret = 0;

    // TODO: add other variables

    ret = (*sys_fstat_ptr)(fd, buf);

    // TODO: perform capsule logic

    // printk("Interceptor fstat(): %s(%d) %d\n", current->comm, fd, current->tgid);

fstat_out:
    return ret;
}

asmlinkage off_t lseek(int fd, off_t offset, int whence) {
    sys_lseek_type  sys_lseek_ptr = (sys_lseek_type) sys_lseek_addr;
    off_t ret = 0;
    curr_ts = 2;

    // TODO: add other variables

    // TODO: perform capsule logic

    ret = (*sys_lseek_ptr)(fd, offset, whence);

    // printk("Interceptor lseek(): %s(%d) %d\n", current->comm, fd, current->tgid);
lseek_out:
    return ret;
}

asmlinkage ssize_t pread64(int fd, void *buf, size_t count, off_t offset) {
    sys_pread64_type    sys_pread64_ptr = (sys_pread64_type) sys_pread64_addr;
    ssize_t ret = 0;

    // TODO: add other variables

    // TODO: perform capsule logic

    ret = (*sys_pread64_ptr)(fd, buf, count, offset);

    // printk("Interceptor pread64(): %s(%d) %d\n", current->comm, fd, current->tgid);
pread64_out:
    return ret;
}

asmlinkage ssize_t read(int fd, void *buf, size_t count) {
    sys_read_type   sys_read_ptr = (sys_read_type) sys_read_addr;
    ssize_t ret = 0;

    curr_ts = 3;

    // TODO: add other variables

    // TODO: perform capsule logic

    ret = (*sys_read_ptr)(fd, buf, count);

    // printk("Interceptor read(): %s(%d) %d\n", current->comm, fd, current->tgid);
read_out:
    return ret;
}

asmlinkage ssize_t write(int fd, const void *buf, size_t count) {
    sys_write_type  sys_write_ptr = (sys_write_type) sys_write_addr;
    ssize_t ret = 0;

    curr_ts = 4;

    // TODO: add other variables

    // TODO: perform capsule logic

    ret = (*sys_write_ptr)(fd, buf, count);

    // printk("Interceptor write(): %s(%d) %d\n", current->comm, fd, current->tgid);
    return ret;
}

asmlinkage void exit(int status) {
    sys_exit_group_type sys_exit_ptr = (sys_exit_group_type) sys_exit_group_addr;

    // TODO: add other variables

    // TODO: perform capsule logic

    // printk("Interceptor exit(): %s(%d) %d\n", current->comm, status, current->tgid);
exit_out:
    (*sys_exit_ptr)(status);
}

// Init stuff
static int optee_match(struct tee_ioctl_version_data *data, const void *vers) {
    return !!1;
}

/* Sets ONE page to rw. Need to figure out how to do a range.
 * Might not be able to.
 */
static void set_pte_rw(unsigned long long addr) {
    pgd_t *pgd_k = pgd_offset_k(addr);
    pud_t *pud_k = pud_offset(pgd_k, addr);
    pmd_t *pmd_k = pmd_offset(pud_k, addr);
    pte_t *pte_k = pte_offset_kernel(pmd_k, addr);

    // printk(KERN_ALERT "addr = %lx, *pgd_k = %p, val_k = %lx\n", addr, pgd_k, pgd_k->pgd);
    // Make a copy
    pte_t pte = *pte_k;

    // Clear the pte rw bit
    // pte_val(pte) &= ~pgprot_val(rw_clear_mask);
    pte = clear_pte_bit(pte, rw_clear_mask);

    // Set the pte bit
    // pte_val(pte) |= pgprot_val(rw_set_mask);
    pte = set_pte_bit(pte, rw_set_mask);

    set_pte(pte_k, pte);
}

/* Sets ONE page to ro. Need to figure out how to do a range.
 * Might not be able to.
 */
static void set_pte_ro(unsigned long long addr) {
    pgd_t *pgd_k = pgd_offset_k(addr);
    pud_t *pud_k = pud_offset(pgd_k, addr);
    pmd_t *pmd_k = pmd_offset(pud_k, addr);
    pte_t *pte_k = pte_offset_kernel(pmd_k, addr);

    // printk(KERN_ALERT "*pgd_k = %p, val_k = %x\n", pgd_k, pgd_k->pgd);
    // Make a copy
    pte_t pte = *pte_k;

    // Clear the pte ro bit
    // pte_val(pte) &= ~pgprot_val(rw_clear_mask);
    pte = clear_pte_bit(pte, ro_clear_mask);

    // Set the pte bit
    // pte_val(pte) |= pgprot_val(rw_set_mask);
    pte = set_pte_bit(pte, ro_set_mask);

    set_pte(pte_k, pte);
}

static void replace_sys_calls(unsigned long long *tbl) {
    // Save the orig syscalls
    // Still need the hikey defines if we want to be compatible
    // with QEMU
    //printk(KERN_ALERT "Address of last syscall %x, index %x\n", (unsigned long long) (tbl+(__NR_syscalls-1)), __NR_syscalls-1);
    unsigned long long addr = 0;
    // sys_open_addr = (func_ptr)*(tbl + __NR_open ); // QEMU
    // sys_lstat_addr      = (func_ptr)*(tbl + __NR_lstat); // QEMU
    // sys_stat_addr       = (func_ptr)*(tbl + __NR_stat); // QEMU
    sys_openat_addr     = (func_ptr)*(tbl + __NR_openat);
    sys_close_addr      = (func_ptr)*(tbl + __NR_close);
    sys_read_addr       = (func_ptr)*(tbl + __NR_read);
    sys_write_addr      = (func_ptr)*(tbl + __NR_write);
    sys_lseek_addr      = (func_ptr)*(tbl + __NR_lseek);
    sys_exit_group_addr = (func_ptr)*(tbl + __NR_exit_group);
    sys_fstat_addr      = (func_ptr)*(tbl + __NR_fstat);
    sys_pread64_addr    = (func_ptr)*(tbl + __NR_pread64);
    sys_newfstatat_addr = (func_ptr)*(tbl + __NR_newfstatat);
    // printk(KERN_ALERT "REPLACE: Address of original openat (%lx)\n", (unsigned long) sys_openat_addr);

    // Replace with our own
    // addr = (unsigned long long) (tbl+(__NR_openat));
    addr = (unsigned long long) (tbl);

    // printk(KERN_ALERT "REPLACE: addresses to replace:");
    // printk(KERN_ALERT "\topenat:\t%lx,\n", (unsigned long) (tbl + __NR_openat));
    // printk(KERN_ALERT "\tclose:\t%lx,\n", (unsigned long) (tbl + __NR_close));
    // printk(KERN_ALERT "\tread:\t%lx,\n", (unsigned long) (tbl + __NR_read));
    // printk(KERN_ALERT "\twrite:\t%lx,\n", (unsigned long) (tbl + __NR_write));
    // printk(KERN_ALERT "\tlseek:\t%lx,\n", (unsigned long) (tbl + __NR_lseek));
    // printk(KERN_ALERT "\texit:\t%lx,\n", (unsigned long) (tbl + __NR_exit_group));
    // printk(KERN_ALERT "\tfstat:\t%lx,\n", (unsigned long) (tbl + __NR_fstat));
    // printk(KERN_ALERT "\tpread64:\t%lx,\n", (unsigned long) (tbl + __NR_pread64));
    // printk(KERN_ALERT "\tfstatat:\t%lx,\n", (unsigned long) (tbl + __NR_newfstatat));

    printk(KERN_ALERT "REPLACE: Setting addr (%lx) to rw\n", addr);
    // set_memory_rw does not work because apply_to_page_range (called by it) uses pgd_offset instead of pgd_offset_k
    set_pte_rw(addr);
    printk(KERN_ALERT "REPLACE: Replacing with our function (%p)\n", (unsigned long*) openat);
    *(tbl + __NR_openat)        = (func_ptr)openat;
    *(tbl + __NR_close)         = (func_ptr)close;
    *(tbl + __NR_read)          = (func_ptr)read;
    *(tbl + __NR_write)         = (func_ptr)write;
    *(tbl + __NR_lseek)         = (func_ptr)lseek;
    *(tbl + __NR_exit_group)    = (func_ptr)exit;
    *(tbl + __NR_fstat)         = (func_ptr)fstat;
    *(tbl + __NR_newfstatat)    = (func_ptr)newfstatat;
    *(tbl + __NR_pread64)       = (func_ptr)pread64;
    // printk(KERN_ALERT "REPLACE: Setting addr (%lx) to ro\n", addr);
    set_pte_ro(addr);
    // printk(KERN_ALERT "REPLACE: Finished, openat: %lx\n", (unsigned long) tbl[__NR_openat]);
}

static void restore_sys_calls(unsigned long long *tbl) {
    unsigned long addr = (unsigned long) (tbl+(__NR_openat));

    printk(KERN_ALERT "RESTORE: Setting addr (%lx) to rw\n", addr);
    set_pte_rw(addr);
    printk(KERN_ALERT "RESTORE: Replacing with old function (%lx)\n", (unsigned long) sys_openat_addr);
    // *(tbl + __NR_open)       = sys_open_addr;
    *(tbl + __NR_openat)        = sys_openat_addr;
    // printk(KERN_ALERT "\tDone... openat\n");
    *(tbl + __NR_close)         = sys_close_addr;
    // printk(KERN_ALERT "\tDone... close\n");
    *(tbl + __NR_read)          = sys_read_addr;
    // printk(KERN_ALERT "\tDone... read\n");
    *(tbl + __NR_write)         = sys_write_addr;
    // printk(KERN_ALERT "\tDone... write\n");
    *(tbl + __NR_lseek)         = sys_lseek_addr;
    // printk(KERN_ALERT "\tDone... lseek\n");
    *(tbl + __NR_fstat)         = sys_fstat_addr;
    // printk(KERN_ALERT "\tDone... fstat\n");
    // *(tbl + __NR_stat)       = sys_stat_addr;
    // *(tbl + __NR_lstat)      = sys_lstat_addr;
    *(tbl + __NR_newfstatat)    = sys_newfstatat_addr;
    // printk(KERN_ALERT "\tDone... newfstatat\n");
    *(tbl + __NR_pread64)       = sys_pread64_addr;
    // printk(KERN_ALERT "\tDone... pread64\n");
    *(tbl + __NR_exit_group)    = sys_exit_group_addr;
    // printk(KERN_ALERT "\tDone... exit\n");
    printk(KERN_ALERT "RESTORE: Setting addr (%lx) to ro\n", addr);
    set_pte_ro(addr);
    printk(KERN_ALERT "RESTORE: Finished, openat: %lx\n", (unsigned long) tbl[__NR_openat]);
}

static int hello_init(void)
{
    // Create the version data (for the context)
    struct tee_ioctl_version_data vers = {
        .impl_id = TEE_OPTEE_CAP_TZ,
        .impl_caps = TEE_IMPL_ID_OPTEE,
        .gen_caps = TEE_GEN_CAP_GP,
    };
    char* buf = kmalloc(MAX_VERSION_LEN, GFP_KERNEL);

    // Clear out the context
    memset(&ctx, 0, sizeof(struct tee_context));

    // Get the context
    ctx = tee_client_open_context(NULL, optee_match, NULL, &vers);

    // Find sys_call_table for this kernel
    find_sys_call_table(acquire_kernel_version(buf), &sys_call_table);
    // printk(KERN_ALERT "Table pointer: %p\nPointer truncated: %lx\n", sys_call_table, (unsigned long) sys_call_table);
    replace_sys_calls(sys_call_table);

    // Print message
    printk( "Finished initializing interceptor module\n" );
    return 0;
}
static void hello_exit(void)
{
    printk("Closing context\n");
    tee_client_close_context(ctx);
    restore_sys_calls(sys_call_table);
    printk(KERN_ALERT "Goodbye, cruel world\n");
}
module_init(hello_init);
module_exit(hello_exit);

MODULE_AUTHOR("UBC");
MODULE_DESCRIPTION("System call interceptor driver");
MODULE_SUPPORTED_DEVICE("");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
