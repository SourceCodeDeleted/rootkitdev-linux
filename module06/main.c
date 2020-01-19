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
MODULE_DESCRIPTION("Simple Hooking Of a Syscall");
MODULE_VERSION("1.0");


unsigned long **SYS_CALL_TABLE;



void EnablePageWriting(void){
	write_cr0(read_cr0() & (~0x10000));

} 
void DisablePageWriting(void){
	write_cr0(read_cr0() | 0x10000);

} 

// bool StartsWith(const char *a, const char *b)
// 	{
// 		if(strncmp(a, b, strlen(b)) == 0) return 1;
// 		return 0;
// 	}


//define our origional function. 
asmlinkage int ( *original_open ) (int dirfd, const char *pathname, int flags); 





//Create Our version of Open Function. 
asmlinkage int	HookOpen(int dirfd, const char *pathname, int flags){

char letter ;
int i = 0;

char directory[255];
char OurFile[14] = "breakpoints"; 


while (letter != 0 || i < 6){ // if (letter == 0x41 || letter < 0x7a) Maybe to prevent bad chars from entering string buffer
	//This macro copies a single simple variable from user space to kernel space. 
	//So this will copy pathname[i] to ch;
	get_user(letter, pathname+i);
	directory[i] = letter ;
	i++;
	}

	if (strcmp(OurFile , directory ) == 0 ){
		printk(KERN_INFO "File Accessed!!! %s", directory);
	}
	memset(directory, 0, 255);

	
	// Jump to origional OpenAt()
	return (*original_open)(dirfd, pathname, flags);
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
	original_open = (void*)SYS_CALL_TABLE[__NR_openat];
	SYS_CALL_TABLE[__NR_openat] = (unsigned long*)HookOpen;
	DisablePageWriting();

	return 0;
}







static void __exit HookCleanup(void) {

	// Clean up our Hooks
	EnablePageWriting();
	SYS_CALL_TABLE[__NR_openat] = (unsigned long*)original_open;
	DisablePageWriting();

	printk(KERN_INFO "HooksCleaned Up!");
}

module_init(SetHooks);
module_exit(HookCleanup);


//STRACE 
/*
root@anonHost:~# strace cat somefile 
execve("/bin/cat", ["cat", "somefile"], 0x7ffd43175fe8 ) = 0
brk(NULL)                               = 0x5614699df000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=169782, ...}) = 0
mmap(NULL, 169782, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f459a155000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\260\34\2\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=2030544, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f459a153000
mmap(NULL, 4131552, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f4599b67000
mprotect(0x7f4599d4e000, 2097152, PROT_NONE) = 0
mmap(0x7f4599f4e000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e7000) = 0x7f4599f4e000
mmap(0x7f4599f54000, 15072, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f4599f54000
close(3)                                = 0
arch_prctl(ARCH_SET_FS, 0x7f459a154540) = 0
mprotect(0x7f4599f4e000, 16384, PROT_READ) = 0
mprotect(0x56146832f000, 4096, PROT_READ) = 0
mprotect(0x7f459a17f000, 4096, PROT_READ) = 0
munmap(0x7f459a155000, 169782)          = 0
brk(NULL)                               = 0x5614699df000
brk(0x561469a00000)                     = 0x561469a00000
openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=4547104, ...}) = 0
mmap(NULL, 4547104, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f4599710000
close(3)                                = 0
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 1), ...}) = 0
openat(AT_FDCWD, "somefile", O_RDONLY)  = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=46, ...}) = 0
fadvise64(3, 0, 0, POSIX_FADV_SEQUENTIAL) = 0
mmap(NULL, 139264, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f459a15d000
read(3, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"..., 131072) = 46
write(1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"..., 46aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
) = 46
read(3, "", 131072)                     = 0
munmap(0x7f459a15d000, 139264)          = 0
close(3)                                = 0
close(1)                                = 0
close(2)                                = 0
exit_group(0)                           = ?
+++ exited with 0 +++

*/