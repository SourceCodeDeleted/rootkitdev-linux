#include "functs.h"



 static void UnLoadDriver(void){

  	unregister_chrdev(Major, DEVICE_NAME);
    printk(KERN_INFO "ROOTKITDEV_DEBUG : Driver Unloaded! \n");
    
 }


 module_exit(UnLoadDriver);

