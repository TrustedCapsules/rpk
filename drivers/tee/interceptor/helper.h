#ifndef HELPER_H
#define HELPER_H

#include <linux/fs_struct.h>

#define IPv4_ADDR_LEN  sizeof("255.255.255.255")
#define MAX_PORT_LEN   5

#ifdef HIKEY
typedef unsigned long long func_ptr;
#else
typedef unsigned long func_ptr;
#endif

typedef asmlinkage int (*sys_open_type)(const char *, int, int);
typedef asmlinkage int (*sys_openat_type)(int, const char *, int, int);
typedef asmlinkage int (*sys_close_type)(int);
typedef asmlinkage off_t (*sys_lseek_type)(int, off_t, int );
typedef asmlinkage ssize_t (*sys_read_type)(int, void *, size_t);
typedef asmlinkage ssize_t (*sys_pread64_type)(int, void *, size_t, off_t);
typedef asmlinkage ssize_t (*sys_write_type)(int, const void *, size_t);
typedef asmlinkage void (*sys_exit_group_type)(int);
typedef asmlinkage int (*sys_fstat_type)(int fd, struct stat *buf);
typedef asmlinkage int (*sys_lstat_type)(const char* path, struct stat *buf);
typedef asmlinkage int (*sys_stat_type)(const char* path, struct stat *buf);
typedef asmlinkage int (*sys_newfstatat_type)(int dirfd, const char *pathname,
											  struct stat *buf, int flags);

char* get_pwd_path( char* pwd_path, int pwd_len, int *path_len );
char* get_path_from_fd( int fd, char* name, int len );
char* get_ipv4_ip_port( int fd, char* name, int len );
off_t get_fpos( int fd );
int path_to_hash_key( char* path, int len );
int is_capsule( const char* filename, int* id );
int is_reg_file( int fd );
int is_ipv4_socket( int fd );

//int is_supplicant();
//int get_sock_information( int fd, char* ip, char* port );
//int get_file_information( int fd, char* filename );

#endif
