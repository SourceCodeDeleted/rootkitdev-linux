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

#include <linux/in.h>

//#include <math.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/uaccess.h>



MODULE_LICENSE("GPL");
MODULE_AUTHOR("SourceCodeDeleted");
MODULE_DESCRIPTION("Intercept Connection Module");
MODULE_VERSION("1.0");


unsigned long **SYS_CALL_TABLE;



void EnablePageWriting(void){
	write_cr0(read_cr0() & (~0x10000));

} 
void DisablePageWriting(void){
	write_cr0(read_cr0() | 0x10000);

} 

#define TCP 0x2
#define UDP 0x1


/*
struct sockaddr_in {
  __kernel_sa_family_t	sin_family;	 Address family	
  __be16		sin_port;	 Port number			
  struct in_addr	sin_addr;	 Internet address		

   Pad to size of `struct sockaddr'. 
  unsigned char		__pad[__SOCK_SIZE__ - sizeof(short int) -
  sizeof(unsigned short int) - sizeof(struct in_addr)];
};

In memory Ip addresses are stored like so 
01.0.0.127  == 01 00 00 7f

*/




// Place to Store IP String
unsigned char IP[32] = {'\0'};

// This function converts internet to Interger and returns String...
char * inet_ntoa(int HexValue){
		memset(IP, 0, sizeof(IP));

		unsigned char first  = (HexValue >> 24) & 0xff;
		unsigned char second = (HexValue >> 16) & 0xff;
		unsigned char third  = (HexValue >> 8)  & 0xff;
		unsigned char fourth = HexValue         & 0xff;

		size_t size  = sizeof(IP) / sizeof(IP[0]);
		snprintf(IP , size  ,"%d.%d.%d.%d" , fourth, third , second , first);

return IP;
}


asmlinkage int ( *original_Connect ) (int fd, struct sockaddr __user *uservaddr, int addrlen); 
//Create Our version of Open Function.  
asmlinkage int	HookConnect(int fd, struct sockaddr __user *uservaddr, int addrlen){

	struct sockaddr_in addr;

	copy_from_user(&addr, uservaddr, sizeof(struct sockaddr_in));

	int IPHEX            =  addr.sin_addr.s_addr;
	unsigned short PORT  =  addr.sin_port;
	int PROTO            =  addr.sin_family;

	char *IpString   = inet_ntoa(IPHEX);
	

	if(PROTO == TCP){
		printk("TCP CONNECTION STARTED -- TO  %s PORT 0x%x",  IpString, PORT ); 
	}
	if(PROTO == UDP){
		printk("UDP CONNECTION STARTED -- TO  %s PORT 0x%x",  IpString, PORT ); 
	


	}

  return ( *original_Connect ) (fd, uservaddr, addrlen);
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
	original_Connect = (void*)SYS_CALL_TABLE[__NR_connect];
	SYS_CALL_TABLE[__NR_connect] = (unsigned long*)HookConnect;
	DisablePageWriting();

	return 0;
}







static void __exit HookCleanup(void) {

	// Clean up our Hooks
	EnablePageWriting();
	SYS_CALL_TABLE[__NR_connect] = (unsigned long*)original_Connect;
	DisablePageWriting();
	printk(KERN_INFO "HooksCleaned Up!");
}

module_init(SetHooks);
module_exit(HookCleanup);



/*

https://github.com/torvalds/linux/blob/master/net/socket.c




int __sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
	int ret = -EBADF;
	struct fd f;

	f = fdget(fd);
	if (f.file) {
		struct sockaddr_storage address;

		ret = move_addr_to_kernel(uservaddr, addrlen, &address);
		if (!ret)
			ret = __sys_connect_file(f.file, &address, addrlen, 0);
		if (f.flags)
			fput(f.file);
	}

	return ret;
}

SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr,
		int, addrlen)
{
	return __sys_connect(fd, uservaddr, addrlen);
}


enum sock_type {
	SOCK_STREAM	= 1,
	SOCK_DGRAM	= 2,
	SOCK_RAW	= 3,
	SOCK_RDM	= 4,
	SOCK_SEQPACKET	= 5,
	SOCK_DCCP	= 6,
	SOCK_PACKET	= 10,
};


retn from STRACE
connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED (Connection refused)


*/