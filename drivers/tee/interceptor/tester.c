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

#include "../tee_private.h"

#include "helper.h"
#include "util.h"

/* TEE TrustZone context */
struct tee_context *ctx;

/* Address of system call table */
// #ifdef HIKEY
// unsigned long long *sys_call_table = (void*) 0xffffffc000b85000;
// #else
unsigned long long *sys_call_table = NULL;
// #endif

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
 */
DEFINE_MUTEX(sess_lock);
DEFINE_SPINLOCK(proc_lock);

/* Accessed List: procid -> abs file names
 *
 * This keeps track of a set of trusted capsule files that
 * have been accessed by a process.
 */
DEFINE_HASHTABLE(proc_table, 10);

/* Session List: abs filenamkes -> TEE sessoins
 *
 * This keeps track of a set of TEE Sessions for each trusted
 * capsule. Theoretically, one new instance of TEE Session
 * should be created on each TEEC_OpenSession(). The OP-TEE
 * Linuxdriver should also handle concurrent calls into TrustZone.
 * That is why we do not have locks for this data structure.
 * However, this again is not well tested for now. 
 *
 * TODO: double check the TEEC_OpenSession() and driver
 * assumptions.
 */
DEFINE_HASHTABLE(sess_table, 10);


/* RW/RO stuff
 *
 */
pgprot_t ro_clear_mask = __pgprot(PTE_WRITE);
pgprot_t ro_set_mask = __pgprot(PTE_RDONLY);
pgprot_t rw_set_mask = __pgprot(PTE_WRITE);
pgprot_t rw_clear_mask = __pgprot(PTE_RDONLY);

// Our syscalls
asmlinkage int openat(int dirfd, const char *file_name, int flags, int mode) {
    sys_openat_type sys_openat_ptr = (sys_openat_type) sys_openat_addr;

    // TODO: add other variables and check for truncate flag

    int fd = (*sys_openat_ptr)(dirfd, file_name, flags, mode);

    // TODO: Perform capsule logic

open_out:
    printk("Interceptor open(): %s(%d) %d\n", current->comm, fd, current->tgid);
    return fd;
}

asmlinkage int open(const char* file_name, int flags, int mode) {
    return openat(AT_FDCWD, file_name, flags, mode);
}

asmlinkage int close(int fd) {
    sys_close_type  sys_close_ptr = (sys_close_type)sys_close_addr;

    // TODO: perform capsule logic

close_out:
    printk("Interceptor close(): %s(%d) %d\n", current->comm, fd, current->tgid);
    return (*sys_close_ptr)(fd);
}


asmlinkage int lstat(const char *pathname, struct stat *buf) {
    sys_lstat_type  sys_lstat_ptr = (sys_lstat_type) sys_lstat_addr;
    int ret = (*sys_lstat_ptr)(pathname, buf);

    // TODO: perform capsule logic

    printk("Interceptor lstat(): %s(%s) %d\n", current->comm, pathname, current->tgid);
    return ret;
}

asmlinkage int stat(const char *pathname, struct stat *buf) {
    sys_stat_type   sys_stat_ptr = (sys_stat_type) sys_stat_addr;
    int ret = (*sys_stat_ptr)(pathname, buf);

    // TODO: perform capsule logic

    printk("Interceptor stat(): %s(%s) %d\n", current->comm, pathname, current->tgid);
    return ret;
}

asmlinkage int newfstatat(int dirfd, const char *pathname, struct stat *buf,
                          int flags) {
    sys_newfstatat_type sys_newfstatat_ptr = (sys_newfstatat_type) sys_newfstatat_addr;

    // TODO: perform capsule logic

    printk("Interceptor newfstatat(): %s(%s) %d\n", current->comm, pathname, current->tgid);
    return (*sys_newfstatat_ptr)(dirfd, pathname, buf, flags);
}

asmlinkage int fstat(int fd, struct stat *buf) {
    sys_fstat_type  sys_fstat_ptr = (sys_fstat_type) sys_fstat_addr;
    int ret = 0;

    // TODO: add other variables

    ret = (*sys_fstat_ptr)(fd, buf);

    // TODO: perform capsule logic

    printk("Interceptor fstat(): %s(%d) %d\n", current->comm, fd, current->tgid);

fstat_out:
    return ret;
}

asmlinkage off_t lseek(int fd, off_t offset, int whence) {
    sys_lseek_type  sys_lseek_ptr = (sys_lseek_type) sys_lseek_addr;
    off_t ret = 0;

    // TODO: add other variables

    // TODO: perform capsule logic

    ret = (*sys_lseek_ptr)(fd, offset, whence);

    printk("Interceptor lseek(): %s(%d) %d\n", current->comm, fd, current->tgid);
lseek_out:
    return ret;
}

asmlinkage ssize_t pread64(int fd, void *buf, size_t count, off_t offset) {
    sys_pread64_type    sys_pread64_ptr = (sys_pread64_type) sys_pread64_addr;
    ssize_t ret = 0;

    // TODO: add other variables

    // TODO: perform capsule logic

    ret = (*sys_pread64_ptr)(fd, buf, count, offset);

    printk("Interceptor pread64(): %s(%d) %d\n", current->comm, fd, current->tgid);
pread64_out:
    return ret;
}

asmlinkage ssize_t read(int fd, void *buf, size_t count) {
    sys_read_type   sys_read_ptr = (sys_read_type) sys_read_addr;
    ssize_t ret = 0;

    // TODO: add other variables

    // TODO: perform capsule logic

    ret = (*sys_read_ptr)(fd, buf, count);

    printk("Interceptor read(): %s(%d) %d\n", current->comm, fd, current->tgid);
read_out:
    return ret;
}

asmlinkage ssize_t write(int fd, const void *buf, size_t count) {
    sys_write_type  sys_write_ptr = (sys_write_type) sys_write_addr;
    ssize_t ret = 0;

    // TODO: add other variables

    // TODO: perform capsule logic

    ret = (*sys_write_ptr)(fd, buf, count);

    printk("Interceptor write(): %s(%d) %d\n", current->comm, fd, current->tgid);
    return ret;
}

asmlinkage void exit(int status) {
    sys_exit_group_type sys_exit_ptr = (sys_exit_group_type) sys_exit_group_addr;

    // TODO: add other variables

    // TODO: perform capsule logic

    printk("Interceptor exit(): %s(%d) %d\n", current->comm, status, current->tgid);
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
static void set_pte_rw(unsigned long addr) {
    pgd_t *pgd_k = pgd_offset_k(addr);
    pud_t *pud_k = pud_offset(pgd_k, addr);
    pmd_t *pmd_k = pmd_offset(pud_k, addr);
    pte_t *pte_k = pte_offset_kernel(pmd_k, addr);

    // printk(KERN_ALERT "*pgd_k = %p, val_k = %x\n", pgd_k, pgd_k->pgd);
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
static void set_pte_ro(unsigned long addr) {
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
    unsigned long addr = 0;
    sys_openat_addr = (func_ptr)*(tbl+__NR_openat);
    printk(KERN_ALERT "REPLACE: Address of original openat (%lx)\n", (unsigned long) sys_openat_addr);

    // Replace with our own
    addr = (unsigned long) (tbl+(__NR_openat));

    printk(KERN_ALERT "REPLACE: Setting addr (%lx) to rw\n", addr);
    // set_memory_rw does not work because apply_to_page_range (called by it) uses pgd_offset instead of pgd_offset_k
    set_pte_rw(addr);
    printk(KERN_ALERT "REPLACE: Replacing with our function (%p)\n", (unsigned long*) openat);
    *(tbl + __NR_openat) = (unsigned long*) openat;
    printk(KERN_ALERT "REPLACE: Setting addr (%lx) to ro\n", addr);
    set_pte_ro(addr);
    printk(KERN_ALERT "REPLACE: Finished, openat: %lx\n", (unsigned long) tbl[__NR_openat]);
}

static void restore_sys_calls(unsigned long long *tbl) {
    unsigned long addr = (unsigned long) (tbl+(__NR_openat));

    printk(KERN_ALERT "RESTORE: Setting addr (%lx) to rw\n", addr);
    set_pte_rw(addr);
    printk(KERN_ALERT "RESTORE: Replacing with old function (%lx)\n", (unsigned long) sys_openat_addr);
    *(tbl + __NR_openat) = sys_openat_addr;
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
// #ifndef HIKEY
    find_sys_call_table(acquire_kernel_version(buf), &sys_call_table);
    printk(KERN_ALERT "Table pointer: %p\nPointer truncated: %lx\n", sys_call_table, (unsigned long) sys_call_table);
// #endif
    replace_sys_calls(sys_call_table);

    // Print message
    printk( "Finished initializing interceptor module\n" );
    return 0;
}
static void hello_exit(void)
{
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
