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
#include "structures.h"
#include "util.h"

/* TEE TrustZone context */
struct tee_context *ctx;

/* TEE supplicant process name */
static char *_tee_supp_app_name = "tee-supplicant";

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

volatile extern unsigned long long cnt_b1;
volatile extern unsigned long long cnt_b2;
volatile extern int curr_ts;
extern struct benchmarking_driver driver_ts[6];

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
    TEE_Operation	op;
    uint32_t		res;

    // Breakdown params
    unsigned long long  cnt_a1, cnt_a2;
    bool                record = false;

    // Other params
    sys_openat_type     sys_openat_ptr = (sys_openat_type) sys_openat_addr;
    sys_close_type      sys_close_ptr = (sys_close_type) sys_close_addr;
    char*               pwd_path = kmalloc(PATH_MAX - strlen(file_name), GFP_KERNEL);
    char*               abs_file_name;
    char*               path_ptr;
    int                 pwd_len = 0, abs_len = strlen(file_name) + 1, fd = -1, id = 0, found = 0;
    uint32_t            err_origin;
    struct session*     curr_sess = NULL;
    struct process*     curr_proc = NULL;
    struct fd_struct*   curr_fd_struct = NULL;
    bool                truncate = (flags & O_TRUNC) &&
                                   (flags & O_RDWR || flags & O_WRONLY);
    bool                is_cap = is_capsule(file_name, &id);

    // Check to see if there is a truncate flag, this messes with the TC header, so we
    // need to override it.
    if (is_cap && truncate) {
        flags = flags & (~O_TRUNC);
    }

    fd = (*sys_openat_ptr)(dirfd, file_name, flags, mode);
    cnt_a1 = read_cntpct();

    // TODO: why?
    if (fd < 0) {
    	fd = -1;
    }

    // TODO: Perform capsule logic
    if (fd >= 0 && strncmp(_tee_supp_app_name, current->comm,
    						strlen(_tee_supp_app_name)) && is_cap) {
    	curr_ts = 0;
    	record = true;

    	// Get current working directory path name
    	if (file_name[0] != '/') {
    		path_ptr = get_pwd_path(pwd_path, PATH_MAX, &pwd_len);

    		if (pwd_len < 0) {
    			printk("Interceptor open(): current->comm %s "
    				   " pwd path not found\n", current->comm);
    			goto open_out;
    		}
    		abs_len += pwd_len + 1;
    	}

    	// Create absolute file path
    	abs_file_name = kmalloc(abs_len, GFP_KERNEL);
    	if (pwd_len > 0) {
    		memcpy(abs_file_name, path_ptr, pwd_len);
    		abs_file_name[pwd_len] = '/';
    		pwd_len++;
    	}

    	// Create full file path
    	strcpy(abs_file_name + pwd_len, file_name);

    	// Setup operation
    	memset(&op, 0, sizeof(TEE_Operation));
    	op.paramTypes = TEE_PARAM_TYPES(TEE_MEMREF_TEMP_INPUT,
    									TEE_VALUE_INPUT,
    									TEE_NONE, TEE_NONE);
    	op.params[0].tmpref.buffer = abs_file_name;
    	op.params[0].tmpref.size = strlen(abs_file_name);
    	op.params[1].value.a = current->tgid;
    	op.params[1].value.b = fd;

    	// Lock the session table
    	mutex_lock(&sess_lock);

    	hash_for_each_possible( sess_table, curr_sess, hash_list, id ) {
			//printk( "Interceptor open(): current->comm %s abs_file_name %s,"
			//	    " curr_sess->abs_name %s\n", current->comm, abs_file_name,
			//		curr_sess->abs_name );	
			if( curr_sess->id == id ) {
				kfree( abs_file_name );
				abs_file_name = curr_sess->abs_name;
				op.params[0].tmpref.buffer = abs_file_name;
				found = 1; // found a session with correct id
				break;
			}
		}

		// printk( "Interceptor open(): current->comm %s session was found"
		// 		" = %d\n", current->comm, found );
		if( found != 1 ) { // Session not found
			res = TEE_OpenSession(ctx, &sess, &uuid, TEE_LOGIN_PUBLIC, 
							        NULL, &err_origin );
			cnt_a2 = read_cntpct();
			driver_ts[curr_ts].module_op += cnt_b1 - cnt_a1 + 
					                        cnt_a2 - cnt_b2;
			// printk("Interceptor open() - cnt_a2: %llu,"
			// 		" cnt_b2: %llu, cnt_b1: %llu, cnt_a1: %llu,"
			// 		" curr_ts: %d, record: %d\n", cnt_a2, cnt_b2, 
			// 		cnt_b1, cnt_a1, curr_ts, record );
   //          printk("Interceptor open(): driver_ts[%d].module_op = %llu\n", curr_ts, driver_ts[curr_ts].module_op);
			cnt_a1 = read_cntpct();		
			cnt_b1 = 0;
			cnt_b2 = 0;
			if( res != TEE_SUCCESS ) {	
				(*sys_close_ptr)( fd );
				fd = -1;
				printk( "Interceptor open(): current->comm %s "
						"TEE_OpenSession Error res %x origin %x\n", 
						current->comm, res, err_origin ); 			
				mutex_unlock( &sess_lock );
				goto open_out;
			}
		} else {
			sess = curr_sess->sess;
		}

		// printk("Teedev: %p\n", ctx->teedev);

		res = TEE_InvokeCommand(ctx, sess, CAPSULE_OPEN, &op, &err_origin );
		cnt_a2 = read_cntpct();
		driver_ts[curr_ts].module_op += cnt_b1 - cnt_a1 + 
			 						    cnt_a2 - cnt_b2;
		// printk("Interceptor open() - cnt_a2: %llu,"
		// 		" cnt_b2: %llu, cnt_b1: %llu, cnt_a1: %llu,"
		// 		" curr_ts: %d, record: %d\n", cnt_a2, cnt_b2, 
		//      cnt_b1, cnt_a1, curr_ts, record );
		cnt_a1 = read_cntpct();		
		cnt_b1 = 0;
		cnt_b2 = 0;
		if( res != TEE_SUCCESS ) { // Capsule open failed
			(*sys_close_ptr)( fd );
			fd = -1;
			if( found != 1 ) {
				TEE_CloseSession(ctx, sess);
				cnt_a2 = read_cntpct();
				driver_ts[curr_ts].module_op += cnt_b1 - cnt_a1 + cnt_a2 - cnt_b2;
				// printk("Interceptor open() - cnt_a2: %llu,"
				// 		" cnt_b2: %llu, cnt_b1: %llu, cnt_a1: %llu,"
				// 		" curr_ts: %d, record: %d\n", cnt_a2, cnt_b2, 
				// 		cnt_b1, cnt_a1, curr_ts, record );
				cnt_a1 = read_cntpct();		
				cnt_b1 = 0;
				cnt_b2 = 0;
			}		
			printk( "Interceptor open(): TEE_InvokeCommand CAPSULE_OPEN"
					 " Error res %x origin %x\n", res, err_origin ); 			
			mutex_unlock( &sess_lock );
			goto open_out;
		}

		if( truncate ) {
			memset( &op, 0, sizeof( TEE_Operation ) );
			op.paramTypes = TEE_PARAM_TYPES( TEE_VALUE_INPUT, TEE_NONE,
											  TEE_NONE, TEE_NONE );
			op.params[0].value.a = 0;	
			res = TEE_InvokeCommand(ctx, sess, CAPSULE_FTRUNCATE, &op, 
									  &err_origin);
			cnt_a2 = read_cntpct();
			driver_ts[curr_ts].module_op += cnt_b1 - cnt_a1 + 
				 						    cnt_a2 - cnt_b2;
			// printk("Interceptor open() - cnt_a2: %llu,"
			// 		" cnt_b2: %llu, cnt_b1: %llu, cnt_a1: %llu,"
			// 		" curr_ts: %d, record: %d\n", cnt_a2, cnt_b2, 
			// 		cnt_b1, cnt_a1, curr_ts, record );
			cnt_a1 = read_cntpct();		
			cnt_b1 = 0;
			cnt_b2 = 0;
			if( res != TEE_SUCCESS ) { // Ftruncate failed
				(*sys_close_ptr)( fd );
				fd = -1;
				if( found != 1 ) { // No session found
					TEE_CloseSession(ctx, sess);
  					cnt_a2 = read_cntpct();
  					driver_ts[curr_ts].module_op += cnt_b1 - cnt_a1 + cnt_a2 - cnt_b2;
					// printk("Interceptor open() - cnt_a2: %llu,"
					// 		" cnt_b2: %llu, cnt_b1: %llu, cnt_a1: %llu,"
					// 		" curr_ts: %d, record: %d\n", cnt_a2, cnt_b2, 
					// 		cnt_b1, cnt_a1, curr_ts, record );
  					cnt_a1 = read_cntpct();		
					cnt_b1 = 0;
					cnt_b2 = 0;
				}		

				printk( "Interceptor open(): TEE_InvokeCommand"
						" CAPSULE_FTRUNCATE Error res %x origin %x\n", 
						res, err_origin );		
				mutex_unlock( &sess_lock );
				goto open_out;
			}
		}

		if( found != 1 ) { // Create session
			curr_sess = kmalloc( sizeof( struct session ), GFP_KERNEL );
			memset( curr_sess, 0, sizeof( struct session ) );
			curr_sess->sess = sess;
			curr_sess->refcnt = 0;
			curr_sess->abs_name = abs_file_name; 
		    curr_sess->id = id;	
			hash_add( sess_table, &curr_sess->hash_list, id ); 
		}
		// printk("Session refcnt before: %d\n", curr_sess->refcnt);
		curr_sess->refcnt++;
		// printk("Session refcnt after: %d\n", curr_sess->refcnt);
		// printk( "Interceptor open(): current->commm %s %d curr_sess->"
		// 		"refcnt %d...unlocking sess_lock\n", current->comm,
		// 		current->tgid, curr_sess->refcnt );
		/* Unlock the sess table */	
		mutex_unlock( &sess_lock );	
		
		/* Lock proc table */
		spin_lock( &proc_lock );
		//printk( "Interceptor open(): current->comm %s %d locked "
		//		"proc_lock\n", current->comm, current->tgid );	
		/* Look through the table to see if a process table
		 * already exists */
		hash_for_each_possible( proc_table, curr_proc, 
						        hash_list, current->tgid ) {
			if( current->tgid == curr_proc->procid ) {
				found = 2; // found proc?
				break;
			}
		}
	
		//printk( "Interceptor open(): current->comm %s proccess was "
		//  	  " found = %d\n", current->comm, found );
		
		if( found != 2 ) { // no proc found, create one
			curr_proc = kmalloc( sizeof( struct process ), GFP_KERNEL );
			curr_proc->procid = current->tgid;
			INIT_HLIST_HEAD( &curr_proc->fd_list );
			hash_add( proc_table, &curr_proc->hash_list, curr_proc->procid );
		}				
	
		//printk( "Intercept open(): curr_fd_struct list:\n" );
		hlist_for_each_entry( curr_fd_struct, &curr_proc->fd_list, list ) {
			if( curr_fd_struct->sess->id == id && curr_fd_struct->fd == -1 ) {
				//printk( "Interceptor open(): no new curr_fd_struct created\n" );
				curr_fd_struct->fd = fd;
                // Found matching fd_struct
                found = 3;
				break;
			}
			//printk( "%d/%d\n", current->tgid, curr_fd_struct->fd );
		}

		if( found != 3 ) { // No matching fd_struct, make new one
            //printk( "Interceptor open(): new fd_struct created\n" );
			curr_fd_struct = kmalloc( sizeof( struct fd_struct ), GFP_KERNEL );
			curr_fd_struct->fd = fd;
			curr_fd_struct->sess = curr_sess;
			hlist_add_head( &curr_fd_struct->list, &curr_proc->fd_list );		
		}
		//printk( "Interceptor open(): current->comm %s %d unlocking"
		//		" proc_lock\n", current->comm, current->tgid );
		/* Unlock the proc table */
		spin_unlock( &proc_lock );
    }


open_out:
    // printk("Interceptor open(): %s(%d) %d\n", current->comm, fd, current->tgid);
	kfree( pwd_path );
	cnt_a2 = read_cntpct();
	if( record ) {
		driver_ts[curr_ts].module_op += cnt_a2 - cnt_a1;
		// printk("Interceptor open() - cnt_a2: %llu,"
		// 		" cnt_b2: %llu, cnt_b1: %llu, cnt_a1: %llu,"
		// 		" curr_ts: %d, record: %d\n", cnt_a2, cnt_b2, 
		// 		cnt_b1, cnt_a1, curr_ts, record );
	}
    return fd;
}

asmlinkage int open(const char* file_name, int flags, int mode) {
    return openat(AT_FDCWD, file_name, flags, mode);
}

asmlinkage int close(int fd) {
	TEE_Operation op;
	uint32_t res;
	uint32_t err_origin;

    sys_close_type  sys_close_ptr = (sys_close_type)sys_close_addr;
    int found = 0;
    struct process *curr_proc;
    struct fd_struct *curr_fd_struct;

    bool record = false;
    unsigned long long cnt_a1, cnt_a2;
    cnt_a1 = read_cntpct();


    spin_lock(&proc_lock);

  /* Get the process's fd_struct list */
  hash_for_each_possible( proc_table, curr_proc, 
				          hash_list, current->tgid ) {
  	if( current->tgid == curr_proc->procid ) {
		found = 1;
		break;
	}
  }


  /* Get the fd */
  if( found == 1 ) {
	// printk( "Interceptor close(): %d curr_fd_struct list\n", fd );
	hlist_for_each_entry( curr_fd_struct, &curr_proc->fd_list, list ) {
		// printk( "%d/%d\n", current->tgid, curr_fd_struct->fd );
		if( fd == curr_fd_struct->fd ) {
			curr_ts = 1;
			record = true;
  			//printk( "Interceptor close(): found = %d/%d, filename: %s"
			//		"...Unlocking proc_lock\n", curr_proc->procid, 
			//		curr_fd_struct->fd, curr_fd_struct->sess->abs_name );
			curr_fd_struct->fd = -1;
			curr_fd_struct->sess->refcnt--;
			// printk( "Removing %d/%d\n", current->tgid, curr_fd_struct->fd );
			spin_unlock( &proc_lock );
			memset( &op, 0, sizeof( TEE_Operation ) );
  			op.paramTypes = TEE_PARAM_TYPES( TEE_VALUE_INPUT, TEE_NONE,
	  				 	                      TEE_NONE, TEE_NONE );
			op.params[0].value.a = current->tgid;
			op.params[0].value.b = fd;

			res = TEE_InvokeCommand(ctx, curr_fd_struct->sess->sess, 
							          CAPSULE_CLOSE, &op, &err_origin ); 
			//printk( "cnt_b1: %llu\n", cnt_b1 );	
			cnt_a2 = read_cntpct();
  			driver_ts[curr_ts].module_op += cnt_b1 - cnt_a1 + cnt_a2 - cnt_b2;
			//printk(KERN_DEBUG  "Interceptor close() - cnt_a2: %llu, cnt_b2: %llu,"
			//		" cnt_b1: %llu, cnt_a1: %llu, curr_ts: %d, "
			//		" record: %d\n", cnt_a2, cnt_b2, cnt_b1, cnt_a1,
			//	 	curr_ts, record );
  			cnt_a1 = read_cntpct();		
			cnt_b1 = 0;
			cnt_b2 = 0;

			if( res != TEE_SUCCESS ) {
				printk( "Interceptor close(): Invoked CAPSULE_CLOSE error"
						" res %x err_origin %x\n", res, err_origin );
			}
			goto close_out;
		}
	}	
  }

  /* Unlock process lock */
  spin_unlock( &proc_lock );

close_out:
  //printk( "Interceptor close(): exit\n" );
  cnt_a2 = read_cntpct();
  if( record ) {
	driver_ts[curr_ts].module_op += cnt_a2 - cnt_a1;
	//printk(KERN_DEBUG  "Interceptor close() - cnt_a2: %llu, cnt_b2: %llu,"
	//		" cnt_b1: %llu, cnt_a1: %llu, curr_ts: %d, "
	//		" record: %d\n", cnt_a2, cnt_b2, cnt_b1, cnt_a1,
	//	 	curr_ts, record );
  } 
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
	TEE_Operation op;
	uint32_t res;
	uint32_t err_origin;

    sys_fstat_type  sys_fstat_ptr = (sys_fstat_type) sys_fstat_addr;
    int ret = 0;
    struct process *curr_proc;
    struct fd_struct *curr_fd_struct;
    int found = 0;

    ret = (*sys_fstat_ptr)(fd, buf);

if( ret < 0 ) return ret;

  /* Lock proccess lock */ 
  spin_lock( &proc_lock );
  /* Get the process's fd_struct list */
  hash_for_each_possible( proc_table, curr_proc, 
				          hash_list, current->tgid ) {
  	if( current->tgid == curr_proc->procid ) {
		found = 1;
		break;
	}
  }

  /* Get the fd */
  if( found == 1 ) {
	hlist_for_each_entry( curr_fd_struct, &curr_proc->fd_list, list ) {
		if( fd == curr_fd_struct->fd ) {
			spin_unlock( &proc_lock );
			memset( &op, 0, sizeof( TEE_Operation ) );
  			op.paramTypes = TEE_PARAM_TYPES( TEE_VALUE_INPUT, 
							                  TEE_VALUE_OUTPUT,
	  				 	                      TEE_NONE, TEE_NONE );
			op.params[0].value.a = current->tgid;
			op.params[0].value.b = fd;
			res = TEE_InvokeCommand(ctx, curr_fd_struct->sess->sess, 
							          CAPSULE_FSTAT, &op, &err_origin ); 
			if( res != TEE_SUCCESS ) {
				ret = -1;
				printk( "Interceptor fstat(): Invoked CAPSULE_FSTAT error"
						" res %x err_origin %x\n", res, err_origin );
			} else {
				buf->st_size = op.params[1].value.a;
			}
  			printk( "Interceptor fstat(): Current comm %s %d/%d on a trusted capsule (%ld B)\n",
				 	current->comm, current->tgid, fd, buf->st_size );
			goto fstat_exit;
		}
	}	
  }
  /* Unlock process lock */
  spin_unlock( &proc_lock );
fstat_exit:
  return ret;
}

asmlinkage off_t lseek(int fd, off_t offset, int whence) {
	TEE_Operation op;
	uint32_t res;
	uint32_t err_origin;

    sys_lseek_type  sys_lseek_ptr = (sys_lseek_type) sys_lseek_addr;
    off_t ret = 0;
    struct process *curr_proc;
    struct fd_struct *curr_fd_struct;
    int found = 0;

    bool record = false;
    unsigned long long cnt_a1, cnt_a2;

    cnt_a1 = read_cntpct();

  //if( current->tgid == temp_tgid && fd > 4 ) {
  //	printk( "Interceptor lseek(): %s %d/%d (%d B)\n", current->comm, 
  //		 	current->tgid, fd, (int) offset );
  //}
  /* Lock proccess lock */ 
  spin_lock( &proc_lock );

  /* Get the process's fd_struct list */
  hash_for_each_possible( proc_table, curr_proc, 
				          hash_list, current->tgid ) {
  	if( current->tgid == curr_proc->procid ) {
		found = 1;
		break;
	}
  }

  /* Get the fd */
  if( found == 1 ) {
	hlist_for_each_entry( curr_fd_struct, &curr_proc->fd_list, list ) {
		if( fd == curr_fd_struct->fd ) {
			curr_ts = 2;
			record = true;
  			// printk( "Interceptor lseek(): found = %d/%d, filename: %s"
					// " offset: %d\n", curr_proc->procid, curr_fd_struct->fd, 
					// curr_fd_struct->sess->abs_name, (int) offset );
			spin_unlock( &proc_lock );
			memset( &op, 0, sizeof( TEE_Operation ) );
  			op.paramTypes = TEE_PARAM_TYPES( TEE_VALUE_INPUT, 
							                  TEE_VALUE_INPUT,
	  				 	                      TEE_VALUE_OUTPUT, 
											  TEE_NONE );
			op.params[0].value.a = current->tgid;
			op.params[0].value.b = fd;
			op.params[1].value.a = offset;
			if( whence == SEEK_SET ) {
				op.params[1].value.b = START; 
			} else if( whence == SEEK_CUR ) {
				op.params[1].value.b = CUR;
			} else if( whence == SEEK_END ) {
				op.params[1].value.b = END;
			} else {
				ret = -1;
				goto lseek_out;
			}
			res = TEE_InvokeCommand(ctx, curr_fd_struct->sess->sess, 
							          CAPSULE_LSEEK, &op, &err_origin ); 
  			cnt_a2 = read_cntpct();
			//printk(KERN_DEBUG  "driver_ts[curr_ts].module_op: %llu\n",
			//		 driver_ts[curr_ts].module_op );
 			driver_ts[curr_ts].module_op += cnt_b1 - cnt_a1 + cnt_a2 - cnt_b2;
			//printk(KERN_DEBUG  "driver_ts[curr_ts].module_op: %llu\n",
			//		 driver_ts[curr_ts].module_op );
			//printk(KERN_DEBUG  "Interceptor LSEEK() - cnt_a2: %llu, cnt_b2: %llu,"
			//		" cnt_b1: %llu, cnt_a1: %llu, curr_ts: %d, "
			//		"record: %d\n", cnt_a2, cnt_b2, cnt_b1, cnt_a1,
			//	 	curr_ts, record );
  			cnt_a1 = read_cntpct();
			cnt_b1 = 0;
  			cnt_b2 = 0;
			if( res != TEE_SUCCESS ) {
				ret = -1;
				printk( "Interceptor lseek(): Invoked CAPSULE_CLOSE error"
						" res %x err_origin %x\n", res, err_origin );
			} else {
				ret = op.params[2].value.a;
			}
			goto lseek_out;
		}
	}
  }

  /* Unlock process lock */
  spin_unlock( &proc_lock );


    ret = (*sys_lseek_ptr)(fd, offset, whence);

    // printk("Interceptor lseek(): %s(%d) %d\n", current->comm, fd, current->tgid);
lseek_out:
  cnt_a2 = read_cntpct();
  if ( record ) {
	driver_ts[curr_ts].module_op += cnt_a2 - cnt_a1;
	//printk(KERN_DEBUG  "Interceptor LSEEK() - cnt_a2: %llu, cnt_b2: %llu,"
	//		" cnt_b1: %llu, cnt_a1: %llu, curr_ts: %d, "
	//		"record: %d\n", cnt_a2, cnt_b2, cnt_b1, cnt_a1,
	//	 	curr_ts, record );
  }  
    return ret;
}

asmlinkage ssize_t pread64(int fd, void *buf, size_t count, off_t offset) {

  TEE_Operation    op;
  uint32_t       res;
  uint32_t          err_origin;

  ssize_t           ret = 0;
  sys_pread64_type  sys_pread64_ptr = (sys_pread64_type) sys_pread64_addr;
  struct process   *curr_proc;
  struct fd_struct *curr_fd_struct;
  int			    found = 0;

  /* Lock proccess lock */ 
  spin_lock( &proc_lock );
 /*
  if( offset == 0 || offset == 9 ) { 
  	//printk( "Interceptor pread64(): current->comm %s %d/%d/%d (%zu B @ %d)\n",
	//		current->comm, current->tgid, current->pid, fd, count, offset );
  }
  */
  /* Get the process's fd_struct list */
  hash_for_each_possible( proc_table, curr_proc, 
				          hash_list, current->tgid ) {
  	
	if( current->tgid == curr_proc->procid ) {
		found = 1;
		break;
	}
  }

  /* Get the fd */
  if( found == 1 ) {
	hlist_for_each_entry( curr_fd_struct, &curr_proc->fd_list, list ) {
		if( fd == curr_fd_struct->fd ) {
			spin_unlock( &proc_lock );
/*	
			printk( "Interceptor pread64(): Invoked CAPSULE_PREAD (%zu B @ %d)"
				" for %d/%d in sess %s\n", count, (int) offset, current->tgid, 
				fd, curr_fd_struct->sess->abs_name );
*/			
			memset( &op, 0, sizeof( TEE_Operation ) );
  			op.paramTypes = TEE_PARAM_TYPES( TEE_VALUE_INPUT,
						   					  TEE_VALUE_INPUT,	
							                  TEE_MEMREF_TEMP_OUTPUT,
	  				 	                      TEE_NONE );
			op.params[0].value.a = current->tgid;
			op.params[0].value.b = fd;
			op.params[1].value.a = offset;
			op.params[2].tmpref.buffer = buf;
			op.params[2].tmpref.size = count;
			res = TEE_InvokeCommand(ctx, curr_fd_struct->sess->sess, 
							          CAPSULE_PREAD, &op, &err_origin ); 
			if( res != TEE_SUCCESS ) {
				ret = -1;
				printk( "Interceptor pread(): Invoked CAPSULE_PREAD error"
						" res %x err_origin %x\n", res, err_origin );
			} else {
				ret = op.params[2].tmpref.size;
			}
			goto pread64_out;
		}
	}	
  }

  /* Unlock process lock */
  spin_unlock( &proc_lock );

  ret = (*sys_pread64_ptr)(fd, buf, count, offset);

pread64_out:
//printk( "Interceptor read(): exit\n" );
  return ret;
}

asmlinkage ssize_t read(int fd, void *buf, size_t count) {
  TEE_Operation   op;
  uint32_t      res;
  uint32_t         err_origin;

  ssize_t          ret = 0;
  sys_read_type    sys_read_ptr = (sys_read_type) sys_read_addr;
  struct process   *curr_proc;
  struct fd_struct *curr_fd_struct;
  int			    found = 0;

  bool              record = false;
  unsigned long long cnt_a1, cnt_a2;

  cnt_a1 = read_cntpct();

  /* Lock proccess lock */ 
  spin_lock( &proc_lock );

  //if( current->tgid == temp_tgid && fd > 4 ) { 
  //	printk( "Interceptor read(): current->comm %s %d/%d (%zu B)\n", 
//		    current->comm, current->tgid, fd, count );
//  }


  /* Get the process's fd_struct list */
  hash_for_each_possible( proc_table, curr_proc, 
				          hash_list, current->tgid ) {
  	
  	//printk( "Interceptor read(): current->tgid %d, current->comm %s"
	//		" curr_proc->procid\n", current->tgid, current->comm,
	//	    curr_proc->procid );
	if( current->tgid == curr_proc->procid ) {
		found = 1;
		break;
	}
  }

  /* Get the fd */
  if( found == 1 ) {
	hlist_for_each_entry( curr_fd_struct, &curr_proc->fd_list, list ) {
		if( fd == curr_fd_struct->fd ) {
			record = true;
			curr_ts = 3;
			spin_unlock( &proc_lock );
		
			// printk( "Interceptor read(): Invoked CAPSULE_READ"
			// 	" for %d/%d in sess %s\n", current->tgid, fd, 
			// 	curr_fd_struct->sess->abs_name );

			memset( &op, 0, sizeof( TEE_Operation ) );
  			op.paramTypes = TEE_PARAM_TYPES( TEE_VALUE_INPUT, 
							                  TEE_MEMREF_TEMP_OUTPUT,
	  				 	                      TEE_NONE, TEE_NONE );
			op.params[0].value.a = current->tgid;
			op.params[0].value.b = fd;
			op.params[1].tmpref.buffer = buf;
			op.params[1].tmpref.size = count;
			res = TEE_InvokeCommand(ctx, curr_fd_struct->sess->sess, 
							          CAPSULE_READ, &op, &err_origin ); 
  			cnt_a2 = read_cntpct();
			// printk(KERN_DEBUG  "driver_ts[curr_ts].module_op: %llu\n",
			// 		 driver_ts[curr_ts].module_op );
 			driver_ts[curr_ts].module_op = driver_ts[curr_ts].module_op
					                       + ( cnt_b1 - cnt_a1 ) 
										   + ( cnt_a2 - cnt_b2 );
			// printk(KERN_DEBUG  "driver_ts[curr_ts].module_op: %llu\n",
			// 		 driver_ts[curr_ts].module_op );
			// printk(KERN_DEBUG  "Interceptor READ() - cnt_a2: %llu, cnt_b2: %llu, "
			// 		"cnt_b1: %llu, cnt_a1: %llu, curr_ts: %d, "
			// 		"record: %d\n", cnt_a2, cnt_b2, cnt_b1, cnt_a1,
			// 	 	curr_ts, record );
  			cnt_a1 = read_cntpct();
			cnt_b1 = 0;
  			cnt_b2 = 0;
			if( res != TEE_SUCCESS ) {
				ret = -1;
				printk( "Interceptor read(): Invoked CAPSULE_READ error"
						" res %x err_origin %x\n", res, err_origin );
			} else {
				ret = op.params[1].tmpref.size;
			}
			goto read_out;
		}
	}	
  }

  /* Unlock process lock */
  spin_unlock( &proc_lock );

  ret = (*sys_read_ptr)(fd, buf, count );

read_out:
  cnt_a2 = read_cntpct();
  if( record ) {
	// printk(KERN_DEBUG  "driver_ts[curr_ts].module_op: %llu\n",
	// 		driver_ts[curr_ts].module_op );
	driver_ts[curr_ts].module_op = driver_ts[curr_ts].module_op +
		   						   ( cnt_a2 - cnt_a1 );
	// printk(KERN_DEBUG  "driver_ts[curr_ts].module_op: %llu\n",
	// 	    driver_ts[curr_ts].module_op );
	// printk(KERN_DEBUG  "Interceptor READ() - cnt_a2: %llu, cnt_b2: %llu, "
	// 		"cnt_b1: %llu, cnt_a1: %llu, curr_ts: %d, "
	// 		"record: %d\n", cnt_a2, cnt_b2, cnt_b1, cnt_a1,
	// 	 	curr_ts, record );
  }
//printk( "Interceptor read(): exit\n" );
  return ret;

}

// TODO: make sure all sess are converted to uint32_t and used that way
asmlinkage ssize_t write(int fd, const void *buf, size_t count) {
  TEE_Operation     op;
  uint32_t        res;
  uint32_t      sess;
  int sess_set = -1;
  uint32_t           err_origin;
  ssize_t            ret = 0;

  sys_write_type     sys_write_ptr = (sys_write_type) sys_write_addr;
  struct process    *curr_proc = NULL;
  struct fd_struct  *curr_fd_struct = NULL;
  char         	    *path;
  char              *path_name;
  int                found = 0;

  bool               record = false;
  unsigned long long cnt_a1, cnt_a2;

  cnt_a1 = read_cntpct();
  //if( current->tgid == temp_tgid && fd > 4 ) {
  //	printk( "Interceptor write(): %s %d/%d (%zu B)\n", current->comm,
//	 	current->tgid, fd, count );
 // }

  /* Lock proccess lock */ 
  spin_lock( &proc_lock );

  /* Get the process's fd_struct list */
  hash_for_each_possible( proc_table, curr_proc, 
				          hash_list, current->tgid ) {
  	if( current->tgid == curr_proc->procid ) {
		found = 1;
		break;
	}
  }

  /* FIXME: currently, we do not propagate encapsulation */
  /* FIXME: we also do not handle anything other than regular files and
   * ipv4 sockets for now */

  /* Check with every opened capsule if this write to this dest is allowed.
   * If it is a write to a capsule, we also check if that capsule allows the
   * write to itself
   */
  if( found == 1 ) {
  	// printk("Checking if all capsules allow write.\n");
	hlist_for_each_entry( curr_fd_struct, &curr_proc->fd_list, list ) {
	
		// printk( "Interceptor write(): Current comm %s(%d) %d/%d touched a trusted capsule\n", 
		// 		current->comm, fd, current->tgid, curr_fd_struct->fd ); 

		memset( &op, 0, sizeof( TEE_Operation ) );
		op.paramTypes = TEE_PARAM_TYPES( TEE_VALUE_INPUT,
										  TEE_MEMREF_TEMP_INPUT,
										  TEE_NONE, TEE_NONE );
		op.params[0].value.a = current->tgid;
		op.params[0].value.b = fd;

		if( is_ipv4_socket( fd ) ) {
		/* Scenario 1: fd is network IPv4 socket */
			path = kmalloc( IPv4_ADDR_LEN + MAX_PORT_LEN + 1, GFP_KERNEL );
			path_name = get_ipv4_ip_port( fd, path, IPv4_ADDR_LEN + 
													MAX_PORT_LEN + 1 );
		
			op.params[1].tmpref.buffer = (void*) path_name;	
			op.params[1].tmpref.size = strlen( path_name );
		
		} else if( fd == curr_fd_struct->fd ) {
  		/* Scenario 2: fd is the capsule file */
			sess = curr_fd_struct->sess->sess;
			sess_set = 1;
			// printk( "Interceptor write(): is_capsule() fd %d writing to capsule %s\n",
			// 		fd, curr_fd_struct->sess->abs_name );
			continue;

		} else if( is_reg_file( fd ) ) {
  		/* Scenario 3: fd is another file */
			path = kmalloc( PATH_MAX, GFP_KERNEL );
			path_name = get_path_from_fd( fd, path, PATH_MAX );
		
			op.params[1].tmpref.buffer = (void*) path_name;	
			op.params[1].tmpref.size = strlen( path_name );
		
			// printk( "Interceptor write(): is_reg_file() fd %d write to %s (%ld B)\n",
			// 		 fd, path_name, count );
		} else {
		/* This is so our tests work, e.g. printf() to console */
			found = 0;
			break;
		}
		/* FIXME: Unlocking here may or may not be a race with open() 
		 *        once we support multithreading */
		spin_unlock( &proc_lock );
		
		res = TEE_InvokeCommand(ctx, curr_fd_struct->sess->sess,
								  CAPSULE_WRITE_EVALUATE, &op, 
								  &err_origin );
		if( res != TEE_SUCCESS ) {
			ret = -1;
			printk( "Interceptor write(): Invoked CAPSULE_WRITE_EVALUATE"
				    " error res %x err_origin %x for %d/%d in sess %s\n", 
					res, err_origin, current->tgid, fd, 
					curr_fd_struct->sess->abs_name );
			kfree( path );
			break;
		} 
		kfree( path );
		spin_lock( &proc_lock );
	}
  }

  /* Unlock process lock */
  spin_unlock( &proc_lock );


  /* Perform the write */
  if( ret >= 0 && found > 0 ) {
  	if( sess_set == -1 ) {
	/* write is to a regular file or socket */
		// printk( "Interceptor write(): tainted write to a regular file\n" );
  		ret = (*sys_write_ptr)(fd, buf, count );
	} else {
	/* write is to a capsule accessed to this process */
		record = true;
		curr_ts = 4;

		// printk( "Interceptor write(): Invoked CAPSULE_WRITE"
		// 		" for %s %d/%d\n", current->comm, current->tgid, fd );

		memset( &op, 0, sizeof( TEE_Operation ) );
		op.paramTypes = TEE_PARAM_TYPES( TEE_VALUE_INPUT,
										  TEE_MEMREF_TEMP_INPUT,
										  TEE_NONE, TEE_NONE );
		op.params[0].value.a = current->tgid;
		op.params[0].value.b = fd;
		op.params[1].tmpref.buffer = (void*) buf;
	    op.params[1].tmpref.size = count;
		
		res = TEE_InvokeCommand(ctx, sess, CAPSULE_WRITE, &op, &err_origin );
		cnt_a2 = read_cntpct();
		// printk(KERN_DEBUG "TEE_InvokeCommand finished cnt_a2 = read_cntpct");
 		driver_ts[curr_ts].module_op += cnt_b1 - cnt_a1 + 
										cnt_a2 - cnt_b2;
		// printk(KERN_DEBUG  "Interceptor WRITE() - cnt_a2: %llu, cnt_b2: %llu, "
		// 		"cnt_b1: %llu, cnt_a1: %llu, curr_ts: %d, record: %d\n",
		// 		cnt_a2, cnt_b2, cnt_b1, cnt_a1, curr_ts, record );
  		cnt_a1 = read_cntpct();
		cnt_b1 = 0;
  		cnt_b2 = 0;
		if( res != TEE_SUCCESS ) {
			ret = -1;
			printk( "Interceptor write(): Invoked CAPSULE_WRITE"
				    " error res %x err_origin %x for %d/%d in sess %s\n", 
					res, err_origin, current->tgid, fd, 
					curr_fd_struct->sess->abs_name );
			return ret;
		} else {
			ret = op.params[1].tmpref.size;
			//printk( "Interceptor write(): ret %d\n", ret );
		}
	}
  } else if ( ret >= 0 ) { 
  	ret = (*sys_write_ptr)(fd, buf, count );
	// printk( "Interceptor write(): regular\n" );
  }

  cnt_a2 = read_cntpct();
  if( record ) { 
	driver_ts[curr_ts].module_op += cnt_a2 - cnt_a1;
	//printk(KERN_DEBUG  "Interceptor WRITE() - cnt_a2: %llu, cnt_b2: %llu, "
	//		"cnt_b1: %llu, cnt_a1: %llu, curr_ts: %d, record: %d\n",
	//		cnt_a2, cnt_b2, cnt_b1, cnt_a1, curr_ts, record );
  }
//write_exit:
//printk( "Interceptor write(): exit\n" );
  return ret;
}

asmlinkage void exit(int status) {
  TEE_Operation       op;
  uint32_t          res;
  uint32_t             err_origin;

  sys_exit_group_type  sys_exit_ptr = (sys_exit_group_type) sys_exit_group_addr;
  struct process      *curr_proc;
  struct fd_struct    *curr_fd_struct;
  struct fd_struct    *prev_fd_struct = NULL;
  int                  found = 0;

  //printk( "Interceptor exit(): entry\n" );
  /* Lock the proc_lock */
  spin_lock( &proc_lock );

  //printk( "Interceptor exit(): intercepted success\n" );

  /* Look through procid to see if the process has accessed
   * any trusted capsules. If it has, get the pointer to
   * the fd_list
   */
  hash_for_each_possible( proc_table, curr_proc, 
				          hash_list, current->tgid ) {
  	//printk( "Interceptor exit(): found %d...looking for %d\n",
	//		curr_proc->procid, current->tgid );
	if( current->tgid == curr_proc->procid ) {
		found = 1;
		break;
	}
  }

  if ( found == 0 ) {
	spin_unlock( &proc_lock );
	goto exit_out;
  }


  /* Remove the proccess entry from the proc_table */
  hlist_del( &curr_proc->hash_list );

  //printk( "Interceptor exit(): Process exiting, but has accessed"
  //  	    " trusted capsules. Removed %d from proc_list...Unlock"
  //	    " proc_lock\n", curr_proc->procid	);
  /* Unlock the proc_lock */
  spin_unlock( &proc_lock );

  /* Iterate through each fd_struct */
  hlist_for_each_entry( curr_fd_struct, &curr_proc->fd_list, list ) { 
    
	if( prev_fd_struct != NULL ) {
		// printk("kfree of prev_fd_struct 1\n");
		kfree( prev_fd_struct );
		// printk("kfree of prev_fd_struct 1 done\n");
	}

  	/* Lock the sess_lock */
	mutex_lock( &sess_lock ); 

  	/* For each fd_struct, find the session struct and 
   	* decrement its refcnt. If it is 0, remove the session
   	* or if there are still other process that has opened
	* the capsule, just close this fd on the TEE side
	*/
	// printk("Session refcnt before: %d\n", curr_fd_struct->sess->refcnt);
	curr_fd_struct->sess->refcnt--;
	// printk("Session refcnt after: %d\n", curr_fd_struct->sess->refcnt);
	if( curr_fd_struct->sess->refcnt <= 0 ) {
		// printk( "Interceptor exit(): removing session %s->refcnt %d\n", 
		// 		curr_fd_struct->sess->abs_name, 
		// 	    curr_fd_struct->sess->refcnt );	
		hlist_del( &curr_fd_struct->sess->hash_list );
		mutex_unlock( &sess_lock );
		TEE_CloseSession(ctx, curr_fd_struct->sess->sess );


		// printk("kfree of curr_fd_struct->sess->abs_name\n");
		kfree( curr_fd_struct->sess->abs_name );
		// printk("kfree of curr_fd_struct->sess\n");
		kfree( curr_fd_struct->sess );
		// printk("Done with kfree\n");
	} else if( curr_fd_struct->fd > 0 ) {
		// printk( "Interceptor exit(): closing %d/%d for %s\n", 
		// 		curr_proc->procid, curr_fd_struct->fd, 
		// 		curr_fd_struct->sess->abs_name );
		mutex_unlock( &sess_lock );	
		memset( &op, 0, sizeof( TEE_Operation ) );
  		op.paramTypes = TEE_PARAM_TYPES( TEE_VALUE_INPUT, TEE_NONE,
	  			 	                      TEE_NONE, TEE_NONE );
		op.params[0].value.a = current->tgid;
		op.params[0].value.b = curr_fd_struct->fd;
		res = TEE_InvokeCommand(ctx, curr_fd_struct->sess->sess, 
						          CAPSULE_CLOSE, &op, &err_origin ); 
		if( res != TEE_SUCCESS ) {
			printk( "Interceptor close(): Invoked CAPSULE_CLOSE error"
					" res %x err_origin %x\n", res, err_origin );
		}
	} else {
		// printk( "Interceptor exit(): %d fd %d for %s already closed\n",
		// 		curr_proc->procid, curr_fd_struct->fd, 
		// 		curr_fd_struct->sess->abs_name );
		mutex_unlock( &sess_lock );
	}

	prev_fd_struct = curr_fd_struct;
  }

  if( prev_fd_struct != NULL ) {
  	// printk("kfree of prev_fd_struct 2\n");
	kfree( prev_fd_struct );
	// printk("kfree of prev_fd_struct 2 done\n");
  }
  // printk("kfree of curr_proc\n");
  kfree( curr_proc );
  // printk("done\n");

  //printk( "Interceptor exit(): freed all proc, sess, fd_struct\n" );

exit_out:
  //printk( "Interceptor exit(): exit\n" );
  (*sys_exit_ptr)( status );
  /* This will throw a 'noreturn' function does return warning.
   * The kernel gets away with it by using:
   *
   * for(;;) {
   *	cpu_relax();
   * }
   *
   * We'll see if we need it at all.
   */
	for(;;) {
		cpu_relax();
	}
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

    // printk("context teedev: %p\n", ctx->teedev);
    // printk("mutex location: %p\n", &ctx->teedev->mutex);

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
