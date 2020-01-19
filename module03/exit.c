#include <linux/module.h>
#include <linux/kernel.h> // Debug messages
#include <linux/init.h>   //macros
#include <linux/moduleparam.h>
#include <linux/stat.h>


 static void HelloExit(void){

    printk(KERN_INFO "ROOTKITDEV_DEBUG : GOODBYE WORLD \n");
    

 }


module_exit(HelloExit);

