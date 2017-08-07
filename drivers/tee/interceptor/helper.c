#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rculist_bl.h>
#include <linux/sched.h>
#include <linux/seqlock.h>
#include <linux/net.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>

// TODO: double check these includes
#include <capsule.h>
#include <linux/tee_kernel_api.h>
#include "structures.h"
#include "helper.h"

extern func_ptr sys_open_addr;
extern func_ptr sys_openat_addr;
extern func_ptr sys_close_addr;
extern func_ptr sys_read_addr;
extern func_ptr sys_write_addr;
extern func_ptr sys_lseek_addr;
extern func_ptr sys_exit_addr;

static void get_fs_root_and_pwd_rcu( struct fs_struct *fs, 
									 struct path *root, 
									 struct path *pwd ) {
	unsigned seq;

	do {
		seq = read_seqcount_begin( &fs->seq );
		*root = fs->root;
		*pwd = fs->pwd;
	} while( read_seqcount_retry( &fs->seq, seq ) );
}

char* get_pwd_path( char* pwd_path, int pwd_len, int* path_len ) {

	char*           path_ptr;
	struct path 	pwd, root;
	/*
	 * This mirrors SYSCALL_DEFINE2 for getcwd in dcache.c.
	 */

	rcu_read_lock();
	get_fs_root_and_pwd_rcu( current->fs, &root, &pwd );

	*path_len = -ENOENT;	
	if( !d_unlinked(pwd.dentry) ) {
		path_ptr = d_path( ( const struct path* ) &pwd, pwd_path, pwd_len );
		*path_len = strlen( path_ptr );		
	} 
	
	rcu_read_unlock();	

	return path_ptr;
}

char* get_path_from_fd( int fd, char* name, int len ) {
	char 		*pathname;
	struct file *file;
	struct path *path;

	/* We do this as sanity check. We do not cover TOCTTOU
	 * attacks, so if a fd exists, there must be a legit
	 * file backing it. If not, something went wrong and
	 * we return ENOENT. Current if this occurs, we return
	 * the error to the application
	 */
	
	file = fget( fd );	
	path = &file->f_path;
	path_get( path );
	fput( file );

	pathname = d_path( path, name, len );
	path_put( (const struct path*) path );

	/* calling function must check error by IS_ERR( pathname ) */

	return pathname;
}

int is_reg_file( int fd ) {

	/* We do this as sanity check. We do not cover TOCTTOU
	 * attacks, so if a fd exists, there must be a legit
	 * file backing it. If not, something went wrong and
	 * we return ENOENT. Current if this occurs, we return
	 * the error to the application
	 */

	struct file *file = fget( fd );
	
	if( S_ISREG( file->f_inode->i_mode ) ) {
		return 1;
	}
	fput( file );

	return 0;
}

/* This returns the current position of a fd in a process.
 * We used the code from lseek syscall with modifications. 
 */
off_t get_fpos( int fd ) {
	off_t retval;
	struct file *file = fget( fd );
	mutex_lock( &file->f_pos_lock );
	retval = file->f_pos;
	mutex_unlock( &file->f_pos_lock );
	fput( file );
	return retval;
}

char* get_ipv4_ip_port( int fd, char* outstring, int len ) {
	struct socket      *sock;
	struct sockaddr_in  sock_addr;
	int                 sock_addr_len;
	int                 err = 0;
	unsigned char      *src;
	char               *res = NULL;

	sock = sockfd_lookup( fd, &err );
	if( sock == NULL || err < 0 )
		return NULL;

	err = sock->ops->getname( sock, (struct sockaddr* ) &sock_addr, &sock_addr_len, 1 );
	if( err == 0 && len >= IPv4_ADDR_LEN + MAX_PORT_LEN + 1 ) {	
		memset( outstring, '\0', len );
		src = (unsigned char*) ( (void*) &sock_addr.sin_addr );
		
		sprintf( outstring, "%u.%u.%u.%u:%d", 
				 src[0], src[1], src[2], src[3], sock_addr.sin_port );
		res = outstring;
	}

	sockfd_put( sock );
	return res;
}

int is_ipv4_socket( int fd ) {
	struct socket      *sock;
	struct sockaddr_in  sock_addr;
	int                 sock_addr_len;
	int                 err = 0;
	int                 is_socket = 0;

	sock = sockfd_lookup( fd, &err );
	if( sock == NULL || err < 0 )
		return is_socket;

	err = sock->ops->getname( sock, (struct sockaddr* ) &sock_addr, &sock_addr_len, 0 );	
	if( err == 0 && sock_addr_len == sizeof( struct sockaddr_in ) ){
		if( sock_addr.sin_family == AF_INET ) {
			is_socket = 1;
		}
	} 

	sockfd_put( sock );
	return is_socket;
}

int is_capsule( const char* file_name, int* id ) {

	int 	     	  	fd, nr;
	mm_segment_t 	  	oldfs;
	struct TrustedCap   cap;    
	int          	  	found = 0;
	sys_openat_type     sys_openat_ptr = (sys_openat_type) sys_openat_addr;
	sys_close_type    	sys_close_ptr = (sys_close_type) sys_close_addr;
	sys_read_type     	sys_read_ptr = (sys_read_type) sys_read_addr;

	/* This is a hack to allow kernels to read files.
	 * Currently Linux is not meant to do this as the kernel
	 * developers are adamant this should not happen. This is
	 * because if kernel is allowed to read files, then the
	 * kernel would dictate policy of where certain files are.
	 * But we are not using this for that. So the work-around
	 * is to temporarily allow syscalls to work with buffers
	 * allocated in kernel (e.g. set_fs( KERNEL_DS). This
	 * sets the boundary to the entire virtual memory. This
	 * means that the check that sys_read() does to make sure
	 * the buffer is an userspace virtual memory address passes
	 * instead of failing
	 */

	oldfs = get_fs();
	set_fs( KERNEL_DS );

	fd = (*sys_openat_ptr)( AT_FDCWD, file_name, O_RDONLY, 0 );
	if( fd >= 0 ) {
		if( is_reg_file( fd ) ) {
			nr = (*sys_read_ptr)( fd, &cap, sizeof(struct TrustedCap) );
			if( nr > 0 ) {
				if( strncmp( (char*) cap.pad, TRUSTEDCAP, 
							 sizeof(cap.pad) ) == 0 ) {
					*id = *(int*) (void*) cap.aes_id;
					found = 1;
				}
			}
		}
		(*sys_close_ptr)(fd);
	}

	set_fs( oldfs );	

	return found;
}

/* Linux hash table API's take an int32 or int64 as key. We
 * need a way to convert the absolute path to such a key
 */
int path_to_hash_key( char* abs_path, int len ) {
	int acc = 0;
	int i;
	for( i = 0; i < len; i++ ) {
		acc += (int) abs_path[i];
	}
	//printk( "Interceptor path_to_hash_key(): path %s acc %d\n", 
	//		abs_path, acc );
	return acc;
}
