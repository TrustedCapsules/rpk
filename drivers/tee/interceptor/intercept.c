#include <asm/unistd.h>

/*
#ifdef __x86_64__
#include <asm/paravirt.h>
#endif
*/

#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/sched.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/limits.h>
#include <linux/tee_kernel_api.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>

#include <capsule.h>
// #include "tee_client_api.h"
#include "structures.h"
#include "util.h"
#include "helper.h"

#include <linux/tee.h>
#include <linux/tee_drv.h>

/* FIXME: Once this is ported to 64-bit, multi-threaded performance
 *        should be tested. 
 * FIXME: rmmod interceptor crashes the kernel
 *
 */

/* Currently memory allocation is done by calling  kmalloc().
 * However, some other kernel submodules seem to allocate a 
 * large chunk using kmalloc() and then manage it as a cache
 * for itself. In the future, we might want to look into that.
 */

/* TEE supplicant process name */
static char *_tee_supp_app_name = "tee-supplicant";

/* Address of system call table */
#ifdef HIKEY
unsigned long long *sys_call_table = (void*) 0xffffffc000b85000;
#else
unsigned long *sys_call_table = NULL;
#endif

/* Function pointers to original sys calls */
func_ptr sys_open_addr,
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

/* Lock for operations to be atomic.
 * 
 * The ability to handle concurrent operations from
 * multiple processes is not well tested and benchmarked
 * It could be that at some point in the future, it 
 * would be a good idea to use RCU instead of spin_locks
 * in the future.
 */
DEFINE_MUTEX( sess_lock );
DEFINE_SPINLOCK( proc_lock );

/* Accessed List: procid -> abs file names 
 *
 * This keeps track of a set of files accessed by a process 
 * that are trusted capsules.   
 */
DEFINE_HASHTABLE( proc_table, 10 );


/* Session List: abs file names -> TEE sessions 
 *
 * This keeps track of a set of TEE Sessions for each trusted
 * capsule. Theoretically, one new instance of TEE Session should
 * be created on each TEEC_OpenSession(). Theoretically, the
 * OP-TEE Linuxdriver should also handle concurrent calls into
 * TrustZone. That is why we do not have locks here for this
 * data structure. However this again is not well tested for now.
 *
 * FIXME: error handling is not robust at all right now. If TA was
 * to crash, we don't really handle that.
 */

DEFINE_HASHTABLE( sess_table, 10 );

/* TEE TrusteZone Context */
TEEC_Context    ctx; // UPGRADE: this needs to be tee_context

// tee_device object of the actual optee driver.
tee_device dev;

int temp_tgid = -1;

asmlinkage int openat( int dirfd, const char *file_name, int flags, int mode) {
  // UPGRADE: change all of these variables to the respective new structs. They are found
  //       in a couple of the header files (optee_private.h, tee_drv.h, tee.h).
  TEEC_Session     *sess;
  TEEC_Operation    op;
  TEEC_Result       res;
  TEEC_UUID         uuid = CAPSULE_UUID; 
  
  uint32_t          err_origin;
  sys_openat_type   sys_openat_ptr = (sys_openat_type)sys_openat_addr;
  sys_close_type    sys_close_ptr = (sys_close_type)sys_close_addr;
  char             *abs_file_name;
  char         	   *pwd_path = kmalloc( PATH_MAX - strlen( file_name ), GFP_KERNEL );
  char         	   *path_ptr;
  int           	pwd_len = 0, abs_len = strlen(file_name) + 1;
  int           	fd = -1, id = 0, found = 0; 
  struct session   *curr_sess = NULL;
  struct process   *curr_proc = NULL;
  struct fd_struct *curr_fd_struct = NULL;
  bool              truncate = (flags & O_TRUNC) && 
		  					   (flags & O_RDWR || flags & O_WRONLY);
  bool              is_cap = is_capsule( file_name, &id );

  //unsigned long long ts;
  if( is_cap ) { 
  	if( truncate ) {
		printk( "Interceptor open(): 0x%08x\n", flags );
		flags = flags & (~O_TRUNC);
		printk( "Interceptor open(): 0x%08x\n", flags );
	}	
  }

  fd = (*sys_openat_ptr)( dirfd, file_name, flags, mode);
  /*
  if( strstr( file_name, "docdata/299573" ) != NULL ) {
		printk( "Interceptor open(): %s(%d) %d/%d\n", current->comm, fd, current->tgid, fd );
  }
  if( strstr( file_name, "samba/tls/" ) != NULL ) {
		printk( "Interceptor open(): %s(%d) %d/%d\n", current->comm, fd, current->tgid, fd );
  }
  */
  if( fd < 0 ) {
	fd = -1;
  }

  /* We check if the file is a trusted capsule. We do this
   * by having the kernel read the file (more detailed explanation
   * is in helper.c). If it is a capsule, we send it to the TEE.
   *
   * We thought about other models. (1) Have TEE do it. (2) Have
   * supplicant do it from user space.
   *
   * (1) Pitfall is scalability and performance. This would be
   *     4x user<->privileged context switch + 2x secure<->normal
   *     world switch. Also there is a limit on the number of
   *     concurrent sessions that the TEE can open. So we should
   *     filter on this side first for the base case of regular
   *     data.
   *
   * (2) Still requires context switch back to user space. Also
   *     the supplicant would require major modification for
   *     concurrency (e.g., locking, single-thread to multi-thread)
   *
   * TEE can return two events:
   *
   * (1) TEE can handle the trusted capsule. In which case, 
   *     we save the session in the Session List and Accessed List. 
   *
   * (2) TEE cannot handle the trusted capsule. In which case,
   *     we close the session. This can be because the file was not 
   *     found, no keys were provisioned, open policy failed etc.,
   *
   * In either case, we execute the normal sys_open() to get back
   * a fd for our own tracking purpose and to make the application
   * agnostic to this extra layer.
   *
   * If the calling application is the supplicant, we ignore
   * it.
   * 
   * Another thing to improve in the future is that opening a 
   * session and the open invoked command should be the
   * same thing.
   */

  if( fd >= 0 && strncmp( _tee_supp_app_name, current->comm, 
						  strlen(_tee_supp_app_name) ) ) {
  	/*
	if( strstr( file_name, "bio.capsule" ) != NULL ) {
		printk( "Interceptor open(): %s(%d) %d/%d\n", current->comm, fd, current->tgid, fd );
		temp_tgid = current->tgid;
  	}

  	if( strstr( file_name, "test_pdf_NULL_1KB.capsule" ) != NULL ) {
		printk( "Interceptor open(): %s(%d) %d/%d\n", current->comm, fd, current->tgid, fd );
		temp_tgid = current->tgid;
  	}
	*/
	if( is_cap ) {
  		//ts = read_cntpct();
  		//printk( "interceptor open(): %llu\n", ts );
		/* Construct the absolute path name */	
		if( file_name[0] != '/' ) {
			path_ptr = get_pwd_path( pwd_path, PATH_MAX, &pwd_len );	
			if( pwd_len < 0 ) {
				printk( "Interceptor open(): current->comm %s "
						" pwd path not found\n", current->comm );
				goto open_out;
			}
			abs_len += pwd_len + 1;
		}

		abs_file_name = kmalloc( abs_len, GFP_KERNEL );
		if( pwd_len > 0 ) { 
			memcpy( abs_file_name, path_ptr, pwd_len );
			abs_file_name[pwd_len] = '/';
			pwd_len++;
		}	
		strcpy( abs_file_name + pwd_len, file_name ); 	

		/* Serialize the input data - capsule path, fd, process id */
        // TODO: need to change TEEC_Operation to tee_ioctl_open_session_arg.
        //       this also involves changing the types of parameters. Might get
        //       messy because not all parameters necessary exist here.
		memset( &op, 0, sizeof( TEEC_Operation ) );
		op.paramTypes = TEEC_PARAM_TYPES( TEEC_MEMREF_TEMP_INPUT,
										  TEEC_VALUE_INPUT, 
										  TEEC_NONE, TEEC_NONE );
		op.params[0].tmpref.buffer = abs_file_name;
		op.params[0].tmpref.size = strlen( abs_file_name );
		op.params[1].value.a = current->tgid;
		op.params[1].value.b = fd;	
		/* Lock the sess table */
		mutex_lock( &sess_lock );	

		printk( "Interceptor open(): current->comm %s %s by "
				"tgid/fd/id %d/%d/0x%08x...locked sess_lock\n", 
				current->comm, abs_file_name, current->tgid, fd, id );
		//printk( "Interceptor open(): current->comm %s %s %s %s by "
		//		"tgid/fd/id %d/%d/0x%08x...locked sess_lock\n", 
		//		current->comm, abs_file_name, pwd_len > 0 ? path_ptr : "(nothing)",
		//		file_name, current->tgid, fd, id );
		/* Look through the table to see if a session already exists
		 * for this capsule */
		hash_for_each_possible( sess_table, curr_sess, hash_list, id ) {
			//printk( "Interceptor open(): current->comm %s abs_file_name %s,"
			//	    " curr_sess->abs_name %s\n", current->comm, abs_file_name,
			//		curr_sess->abs_name );	
			if( curr_sess->id == id ) {
				kfree( abs_file_name );
				abs_file_name = curr_sess->abs_name;
				op.params[0].tmpref.buffer = abs_file_name;
				found = 1;
				break;
			}
		}

		/* Create a new session if it does not exist. Then call into
		 * the TEE for the open() command:
		 * 
		 * input: pid, fd, abs_name 
		 *
		 * If the operation is allowed. Add the new session to the
		 * table if it does not exist already. Increment the session's
		 * reference count.
		 *
		 * If the operation fails. Free the session if its refcnt is 0.
		 * Call (*sys_close_ptr)() on fd. Set fd to -1.
		 *
		 * Technically, I should check for error at the kmalloc(). But
		 * Meh.
		 */
		//printk( "Interceptor open(): current->comm %s session was found"
		//		" = %d\n", current->comm, found );
		if( found != 1 ) {
			sess = kmalloc( sizeof( TEEC_Session ), GFP_KERNEL );
            // TODO: directly call the optee_open_session method found in call.c
            //       header file optee_private.h
            //       TEEC_LOGIN_PUBLIC macro found in the tee.h file
			res = TEEC_OpenSession( &ctx, sess, &uuid, TEEC_LOGIN_PUBLIC, 
							        NULL, NULL, &err_origin );
			if( res != TEEC_SUCCESS ) {	
				(*sys_close_ptr)( fd );
				fd = -1;
				kfree( sess );
				printk( "Interceptor open(): current->comm %s "
						"TEEC_OpenSession Error res %x origin %x\n", 
						current->comm, res, err_origin ); 			
				mutex_unlock( &sess_lock );
				goto open_out;
			}
		} else {
			sess = curr_sess->sess;
		}
		// TODO: replace with optee_invoke_func and the tee_ioctl_invoke_arg struct.
		res = TEEC_InvokeCommand( sess, CAPSULE_OPEN, &op, &err_origin );
		if( res != TEEC_SUCCESS ) {
			(*sys_close_ptr)( fd );
			fd = -1;
			if( found != 1 ) {
				TEEC_CloseSession( sess );
				kfree( sess );	
			}		
			printk( "Interceptor open(): TEEC_InvokeCommand CAPSULE_OPEN"
					 " Error res %x origin %x\n", res, err_origin ); 			
			mutex_unlock( &sess_lock );
			goto open_out;
		}
		
		if( truncate ) {
			memset( &op, 0, sizeof( TEEC_Operation ) );
			op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT, TEEC_NONE,
											  TEEC_NONE, TEEC_NONE );
			op.params[0].value.a = 0;	
            // TODO: replace with optee_invoke_func and the tee_ioctl_invoke_arg struct
			res = TEEC_InvokeCommand( sess, CAPSULE_FTRUNCATE, &op, 
									  &err_origin );
			if( res != TEEC_SUCCESS ) {
				(*sys_close_ptr)( fd );
				fd = -1;
				if( found != 1 ) {
                    // TODO: replace with the optee_close_session call. Requires a tee_context
                    //       struct and a u32 session
					TEEC_CloseSession( sess );
					kfree( sess );	
				}		
				printk( "Interceptor open(): TEEC_InvokeCommand"
						" CAPSULE_FTRUNCATE Error res %x origin %x\n", 
						res, err_origin );		
				mutex_unlock( &sess_lock );
				goto open_out;
			}
		}
		
		if( found != 1 ) {
			curr_sess = kmalloc( sizeof( struct session ), GFP_KERNEL );
			memset( curr_sess, 0, sizeof( struct session ) );
			curr_sess->sess = sess;
			curr_sess->refcnt = 0;
			curr_sess->abs_name = abs_file_name; 
		    curr_sess->id = id;	
			hash_add( sess_table, &curr_sess->hash_list, id ); 
		}	
		curr_sess->refcnt++;	
		//printk( "Interceptor open(): current->commm %s %d curr_sess->"
		//		"refcnt %d...unlocking sess_lock\n", current->comm,
		//		current->tgid, curr_sess->refcnt );
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
				found = 2;
				break;
			}
		}
	
		//printk( "Interceptor open(): current->comm %s proccess was "
		//  	  " found = %d\n", current->comm, found );
		
		if( found != 2 ) {
			curr_proc = kmalloc( sizeof( struct process ), GFP_KERNEL );
			curr_proc->procid = current->tgid;
			INIT_HLIST_HEAD( &curr_proc->fd_list );
			hash_add( proc_table, &curr_proc->hash_list, curr_proc->procid );
		}				
	
		printk( "Intercept open(): curr_fd_struct list:\n" );
		hlist_for_each_entry( curr_fd_struct, &curr_proc->fd_list, list ) {
			if( curr_fd_struct->sess->id == id && curr_fd_struct->fd == -1 ) {
				//printk( "Interceptor open(): no new curr_fd_struct created\n" );
				curr_fd_struct->fd = fd;
				found = 3;
				break;
			}
			printk( "%d/%d\n", current->tgid, curr_fd_struct->fd );
		}

		if( found != 3 ) {
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
  }

open_out:
  //printk( "Interceptor open(): exit\n" );
  kfree( pwd_path );
  return fd; 
}

asmlinkage int open( const char* file_name, int flags, int mode ) {
  return openat( AT_FDCWD, file_name, flags, mode );	
}

asmlinkage int close(int fd) {
  // TODO: Change to have correct equivalents. The TEEC_Operation is split into
  //       different ioctl arg types.
  TEEC_Operation    op;
  TEEC_Result       res;
  uint32_t          err_origin;

  sys_close_type    sys_close_ptr = (sys_close_type)sys_close_addr;
  int               found = 0;
  struct process   *curr_proc;
  struct fd_struct *curr_fd_struct;
/* 
  if( current->tgid == temp_tgid && fd > 4 ) { 
  	printk( "Interceptor close(): %s %d/%d\n", 
			current->comm, current->tgid, fd );
  }
  */
  /* Lock process lock */
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
	printk( "Interceptor close(): %d curr_fd_struct list\n", fd );
	hlist_for_each_entry( curr_fd_struct, &curr_proc->fd_list, list ) {
		printk( "%d/%d\n", current->tgid, curr_fd_struct->fd );
		if( fd == curr_fd_struct->fd ) {
  			//printk( "Interceptor close(): found = %d/%d, filename: %s"
			//		"...Unlocking proc_lock\n", curr_proc->procid, 
			//		curr_fd_struct->fd, curr_fd_struct->sess->abs_name );
			curr_fd_struct->fd = -1;
			printk( "Removing %d/%d\n", current->tgid, curr_fd_struct->fd );
			spin_unlock( &proc_lock );
			memset( &op, 0, sizeof( TEEC_Operation ) );
  			op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT, TEEC_NONE,
	  				 	                      TEEC_NONE, TEEC_NONE );
			op.params[0].value.a = current->tgid;
			op.params[0].value.b = fd;

            // TODO: change to optee_invoke_func and appropriate arg type
			res = TEEC_InvokeCommand( curr_fd_struct->sess->sess, 
							          CAPSULE_CLOSE, &op, &err_origin ); 
			if( res != TEEC_SUCCESS ) {
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
  return (*sys_close_ptr)(fd);
}

asmlinkage int lstat( const char *pathname, struct stat *buf ) {
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

asmlinkage int stat( const char *pathname, struct stat *buf ) {
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


asmlinkage int newfstatat( int dirfd, const char *pathname, struct stat *buf,
						   int flags ) {
	sys_newfstatat_type sys_newfstatat_ptr = (sys_newfstatat_type) sys_newfstatat_addr;
	//printk( "Intercepted this newfstatat call\n" );
	return (*sys_newfstatat_ptr)(dirfd, pathname, buf, flags);
}


asmlinkage int fstat( int fd, struct stat *buf ) {
  TEEC_Operation    op;
  TEEC_Result       res;
  uint32_t          err_origin;
		
  int 		    	ret = 0;
  sys_fstat_type    sys_fstat_ptr = (sys_fstat_type) sys_fstat_addr;
  struct process   *curr_proc;
  struct fd_struct *curr_fd_struct;
  int               found = 0;
/*
  if( current->tgid == temp_tgid && fd > 4 ) {
  	//printk( "Interceptor fstat(): %s %d/%d\n", current->comm, 
	//	 	current->tgid, fd );
  }
  */
  ret = (*sys_fstat_ptr)( fd, buf );
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
			memset( &op, 0, sizeof( TEEC_Operation ) );
  			op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT, 
							                  TEEC_VALUE_OUTPUT,
	  				 	                      TEEC_NONE, TEEC_NONE );
			op.params[0].value.a = current->tgid;
			op.params[0].value.b = fd;
			res = TEEC_InvokeCommand( curr_fd_struct->sess->sess, 
							          CAPSULE_FSTAT, &op, &err_origin ); 
			if( res != TEEC_SUCCESS ) {
				ret = -1;
				printk( "Interceptor fstat(): Invoked CAPSULE_FSTAT error"
						" res %x err_origin %x\n", res, err_origin );
			} else {
				buf->st_size = op.params[1].value.a;
			}
  			//printk( "Interceptor fstat(): Current comm %s %d/%d on a trusted capsule (%ld B)\n",
			//	 	current->comm, current->tgid, fd, buf->st_size );
			goto fstat_exit;
		}
	}	
  }
  /* Unlock process lock */
  spin_unlock( &proc_lock );
fstat_exit:
  return ret;
}
asmlinkage off_t lseek( int fd, off_t offset, int whence ) {
  TEEC_Operation    op;
  TEEC_Result       res;
  uint32_t          err_origin;
		
  off_t 		    ret = 0;
  sys_lseek_type    sys_lseek_ptr = (sys_lseek_type) sys_lseek_addr;
  struct process   *curr_proc;
  struct fd_struct *curr_fd_struct;
  int               found = 0;

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
  			//printk( "Interceptor lseek(): found = %d/%d, filename: %s"
			//		" offset: %d\n", curr_proc->procid, curr_fd_struct->fd, 
			//		curr_fd_struct->sess->abs_name, (int) offset );
			spin_unlock( &proc_lock );
			memset( &op, 0, sizeof( TEEC_Operation ) );
  			op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT, 
							                  TEEC_VALUE_INPUT,
	  				 	                      TEEC_VALUE_OUTPUT, 
											  TEEC_NONE );
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
			res = TEEC_InvokeCommand( curr_fd_struct->sess->sess, 
							          CAPSULE_LSEEK, &op, &err_origin ); 
			if( res != TEEC_SUCCESS ) {
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

  ret = (*sys_lseek_ptr)( fd, offset, whence );

lseek_out: 
  //printk( "Interceptor lseek(): exit\n" );
  return ret;
}

asmlinkage ssize_t pread64(int fd, void *buf, size_t count, off_t offset) {

  TEEC_Operation    op;
  TEEC_Result       res;
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
			memset( &op, 0, sizeof( TEEC_Operation ) );
  			op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT,
						   					  TEEC_VALUE_INPUT,	
							                  TEEC_MEMREF_TEMP_OUTPUT,
	  				 	                      TEEC_NONE );
			op.params[0].value.a = current->tgid;
			op.params[0].value.b = fd;
			op.params[1].value.a = offset;
			op.params[2].tmpref.buffer = buf;
			op.params[2].tmpref.size = count;
			res = TEEC_InvokeCommand( curr_fd_struct->sess->sess, 
							          CAPSULE_PREAD, &op, &err_origin ); 
			if( res != TEEC_SUCCESS ) {
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
  TEEC_Operation   op;
  TEEC_Result      res;
  uint32_t         err_origin;

  ssize_t          ret = 0;
  sys_read_type    sys_read_ptr = (sys_read_type) sys_read_addr;
  struct process   *curr_proc;
  struct fd_struct *curr_fd_struct;
  int			    found = 0;

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
			spin_unlock( &proc_lock );
		
			//printk( "Interceptor read(): Invoked CAPSULE_READ"
			//	" for %d/%d in sess %s\n", current->tgid, fd, 
			//	curr_fd_struct->sess->abs_name );

			memset( &op, 0, sizeof( TEEC_Operation ) );
  			op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT, 
							                  TEEC_MEMREF_TEMP_OUTPUT,
	  				 	                      TEEC_NONE, TEEC_NONE );
			op.params[0].value.a = current->tgid;
			op.params[0].value.b = fd;
			op.params[1].tmpref.buffer = buf;
			op.params[1].tmpref.size = count;
			res = TEEC_InvokeCommand( curr_fd_struct->sess->sess, 
							          CAPSULE_READ, &op, &err_origin ); 
			if( res != TEEC_SUCCESS ) {
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
//printk( "Interceptor read(): exit\n" );
  return ret;
}

asmlinkage ssize_t write(int fd, const void *buf, size_t count) {
  TEEC_Operation     op;
  TEEC_Result        res;
  TEEC_Session      *sess = NULL;
  uint32_t           err_origin;
  ssize_t            ret = 0;

  sys_write_type     sys_write_ptr = (sys_write_type) sys_write_addr;
  struct process    *curr_proc = NULL;
  struct fd_struct  *curr_fd_struct = NULL;
  char         	    *path;
  char              *path_name;
  int                found = 0;

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
	hlist_for_each_entry( curr_fd_struct, &curr_proc->fd_list, list ) {
	
		// printk( "Interceptor write(): Current comm %s(%d) %d/%d touched a trusted capsule\n", 
				// current->comm, fd, current->tgid, curr_fd_struct->fd ); 

		memset( &op, 0, sizeof( TEEC_Operation ) );
		op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT,
										  TEEC_MEMREF_TEMP_INPUT,
										  TEEC_NONE, TEEC_NONE );
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
			printk( "Interceptor write(): is_capsule() fd %d writing to capsule %s\n",
					fd, curr_fd_struct->sess->abs_name );
			continue;

		} else if( is_reg_file( fd ) ) {
  		/* Scenario 3: fd is another file */
			path = kmalloc( PATH_MAX, GFP_KERNEL );
			path_name = get_path_from_fd( fd, path, PATH_MAX );
		
			op.params[1].tmpref.buffer = (void*) path_name;	
			op.params[1].tmpref.size = strlen( path_name );
		
			//printk( "Interceptor write(): is_reg_file() fd %d write to %s (%ld B)\n",
		//			 fd, path_name, count );
		
		} else {
		/* This is so our tests work, e.g. printf() to console */
			found = 0;
			break;
		}
		/* FIXME: Unlocking here may or may not be a race with open() 
		 *        once we support multithreading */
		spin_unlock( &proc_lock );
		
		res = TEEC_InvokeCommand( curr_fd_struct->sess->sess,
								  CAPSULE_WRITE_EVALUATE, &op, 
								  &err_origin );
		if( res != TEEC_SUCCESS ) {
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
  	if( sess == NULL ) {
	/* write is to a regular file or socket */
		printk( "Interceptor write(): tainted write to a regular file\n" );
  		ret = (*sys_write_ptr)(fd, buf, count );
	} else {
	/* write is to a capsule accessed to this process */

		printk( "Interceptor write(): Invoked CAPSULE_WRITE"
				" for %s %d/%d\n", current->comm, current->tgid, fd );

		memset( &op, 0, sizeof( TEEC_Operation ) );
		op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT,
										  TEEC_MEMREF_TEMP_INPUT,
										  TEEC_NONE, TEEC_NONE );
		op.params[0].value.a = current->tgid;
		op.params[0].value.b = fd;
		op.params[1].tmpref.buffer = (void*) buf;
	    op.params[1].tmpref.size = count;
		
		res = TEEC_InvokeCommand( sess, CAPSULE_WRITE, &op, &err_origin );
		if( res != TEEC_SUCCESS ) {
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
	//printk( "Interceptor write(): regular\n" );
  }

//write_exit:
//printk( "Interceptor write(): exit\n" );
  return ret;
}

asmlinkage void exit( int status ) {
  TEEC_Operation       op;
  TEEC_Result          res;
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

  //printk( "Interceptor exit(): Process exiting, but has accesed"
  //  	    " trusted capsules. Removed %d from proc_list...Unlock"
  //	    " proc_lock\n", curr_proc->procid	);
  /* Unlock the proc_lock */
  spin_unlock( &proc_lock );

  /* Iterate through each fd_struct */
  hlist_for_each_entry( curr_fd_struct, &curr_proc->fd_list, list ) { 
    
	if( prev_fd_struct != NULL ) {
		kfree( prev_fd_struct );
	}

  	/* Lock the sess_lock */
	mutex_lock( &sess_lock ); 

  	/* For each fd_struct, find the session struct and 
   	* decrement its refcnt. If it is 0, remove the session
   	* or if there are still other process that has opened
	* the capsule, just close this fd on the TEE side
	*/
	curr_fd_struct->sess->refcnt--;
	if( curr_fd_struct->sess->refcnt <= 0 ) {
		printk( "Interceptor exit(): removing session %s->refcnt %d\n", 
				curr_fd_struct->sess->abs_name, 
			    curr_fd_struct->sess->refcnt );	
		hlist_del( &curr_fd_struct->sess->hash_list );
		mutex_unlock( &sess_lock );
		TEEC_CloseSession( curr_fd_struct->sess->sess );
			
		kfree( curr_fd_struct->sess->abs_name );
		kfree( curr_fd_struct->sess->sess );	
		kfree( curr_fd_struct->sess );
	} else if( curr_fd_struct->fd > 0 ) {
		printk( "Interceptor exit(): closing %d/%d for %s\n", 
				curr_proc->procid, curr_fd_struct->fd, 
				curr_fd_struct->sess->abs_name );
		mutex_unlock( &sess_lock );	
		memset( &op, 0, sizeof( TEEC_Operation ) );
  		op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT, TEEC_NONE,
	  			 	                      TEEC_NONE, TEEC_NONE );
		op.params[0].value.a = current->tgid;
		op.params[0].value.b = curr_fd_struct->fd;
		res = TEEC_InvokeCommand( curr_fd_struct->sess->sess, 
						          CAPSULE_CLOSE, &op, &err_origin ); 
		if( res != TEEC_SUCCESS ) {
		//	printk( "Interceptor close(): Invoked CAPSULE_CLOSE error"
		//			" res %x err_origin %x\n", res, err_origin );
		}
	} else {
		printk( "Interceptor exit(): %d fd %d for %s already closed\n",
				curr_proc->procid, curr_fd_struct->fd, 
				curr_fd_struct->sess->abs_name );
		mutex_unlock( &sess_lock );
	}

	prev_fd_struct = curr_fd_struct;
  }

  if( prev_fd_struct != NULL ) {
	kfree( prev_fd_struct );
  }
  kfree( curr_proc );

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

/* On X86, there are these guard registers that protect
 * the system call table. Therefore the write_cr0 is 
 * used to turn those guards off. We are not sure if
 * these exists on ARM, but they seem to work fine in
 * QEMU so far.
 */
#ifdef HIKEY
static void replace_sys_calls(unsigned long long *tbl) {
#else
static void replace_sys_calls(unsigned long *tbl) {
#endif

#ifdef __x86_64__
  write_cr0(read_cr0() & (~0x10000));
#endif

  // Save the addresses of original sys calls.
#ifndef HIKEY
  sys_open_addr = (func_ptr)*(tbl + __NR_open );
#endif
  sys_openat_addr     = (func_ptr)*(tbl + __NR_openat);
  sys_close_addr      = (func_ptr)*(tbl + __NR_close);
  sys_read_addr       = (func_ptr)*(tbl + __NR_read);
  sys_write_addr      = (func_ptr)*(tbl + __NR_write);
  sys_lseek_addr      = (func_ptr)*(tbl + __NR_lseek);
  sys_exit_group_addr = (func_ptr)*(tbl + __NR_exit_group);
  sys_fstat_addr      = (func_ptr)*(tbl + __NR_fstat);
#ifndef HIKEY
  sys_lstat_addr      = (func_ptr)*(tbl + __NR_lstat);
  sys_stat_addr       = (func_ptr)*(tbl + __NR_stat);
#endif
#ifdef HIKEY
  sys_pread64_addr    = (func_ptr)*(tbl + __NR_pread64);
  sys_newfstatat_addr = (func_ptr)*(tbl + __NR_newfstatat);
#endif
  // Hijack the system calls with our own.

#ifndef HIKEY
  *(tbl + __NR_open)        = (func_ptr)open;
#endif
  *(tbl + __NR_openat) 		= (func_ptr)openat;
  *(tbl + __NR_close) 		= (func_ptr)close;
  *(tbl + __NR_read)  		= (func_ptr)read;
  *(tbl + __NR_write) 		= (func_ptr)write;
  *(tbl + __NR_lseek) 		= (func_ptr)lseek;
  *(tbl + __NR_exit_group ) = (func_ptr)exit;
  *(tbl + __NR_fstat)       = (func_ptr)fstat;
#ifndef HIKEY
  *(tbl + __NR_stat)  		= (func_ptr)stat;
  *(tbl + __NR_lstat) 		= (func_ptr)lstat;
#endif
#ifdef HIKEY
  *(tbl + __NR_newfstatat)  = (func_ptr)newfstatat;
  *(tbl + __NR_pread64)     = (func_ptr)pread64;
#endif
#ifdef __x86_64__
  write_cr0(read_cr0() | 0x10000);
#endif

}

#ifdef HIKEY
static void restore_sys_calls(unsigned long long *tbl) {
#else
static void restore_sys_calls(unsigned long *tbl) {
#endif

#ifdef __x86_64__
  write_cr0(read_cr0() & (~0x10000));
#endif

#ifndef HIKEY
  *(tbl + __NR_open) = sys_open_addr;
#endif
  *(tbl + __NR_openat)  = sys_openat_addr;
  *(tbl + __NR_close) = sys_close_addr;
  *(tbl + __NR_read)  = sys_read_addr;
  *(tbl + __NR_write) = sys_write_addr;
  *(tbl + __NR_lseek) = sys_lseek_addr;
  *(tbl + __NR_fstat) = sys_fstat_addr;
#ifndef HIKEY
  *(tbl + __NR_stat)  = sys_stat_addr;
  *(tbl + __NR_lstat) = sys_lstat_addr;
#endif
#ifdef HIKEY
  *(tbl + __NR_newfstatat)  = sys_newfstatat_addr;
  *(tbl + __NR_pread64) = sys_pread64_addr;
#endif
//  *(tbl + __NR_exit)  = sys_exit_addr; 
  *(tbl + __NR_exit_group) = sys_exit_group_addr;
#ifdef __x86_64__
  write_cr0(read_cr0() | 0x10000);
#endif

}

// Don't necessarily need a TEEC context. It is 
// implementation defined. If I call driver functions
// directly, I will need something to determine the
// context.
int __init init_my_module(void) {
  TEEC_Result res;
  memset( &ctx, 0, sizeof( TEEC_Context ) );

  /* Initialize TEE */
  res = TEEC_InitializeContext( NULL, &ctx );
  if( res != TEEC_SUCCESS ) {
  	return 0;
  }

  /* Replace the syscalls */	  
#ifndef HIKEY 
  find_sys_call_table("-3.18.0-linaro-hikey", &sys_call_table);
#endif
  replace_sys_calls(sys_call_table);

  printk( "Finished initializing interceptor module\n" );

  return 0;
}

void __exit cleanup_my_module(void) {
  if( ctx.fd ) {
	/* Restore the syscalls */
  	restore_sys_calls(sys_call_table);

  	TEEC_FinalizeContext( &ctx );
  }

  printk( "Removed interceptor module\n" );
  return;
}

module_init(init_my_module);
module_exit(cleanup_my_module);

MODULE_AUTHOR("UBC");
MODULE_DESCRIPTION("System call interceptor driver");
MODULE_SUPPORTED_DEVICE("");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
