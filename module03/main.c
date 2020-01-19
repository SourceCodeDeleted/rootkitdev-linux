#include <linux/module.h>
#include <linux/kernel.h> // Debug messages
#include <linux/init.h>   //macros
#include <linux/moduleparam.h>
#include <linux/stat.h>


MODULE_LICENSE("GPL");

#define DRIVER_AUTHOR "SourceCodeDeleted"
#define DRIVER_DESC "Some hello world param driver"
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);


//MODULE_SUPPORTED_DEVICE("testdevice");


static char *MyString = "";
module_param(MyString, charp, 0000);
MODULE_PARM_DESC(MyString, "This is a string that gets echoed.");


 static int HelloInit(void){

    printk(KERN_INFO "ROOTKITDEV_DEBUG: %s \n", MyString);
    return 0; 
 }
 



module_init(HelloInit);

