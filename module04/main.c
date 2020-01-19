#include "functs.h"



MODULE_LICENSE("GPL");

#define DRIVER_AUTHOR "SourceCodeDeleted"
#define DRIVER_DESC "Some hello world param driver"
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);

int Major;
static int Device_Open = 0;
static char msg[BUF_LEN]={0};
static char *msg_Ptr;

static struct file_operations fops = {
    .read    = device_read,
    .write   = device_write,
    .open    = device_open,
    .release = device_release
};



//init _module functions

int init_module(void){

Major = register_chrdev(0, DEVICE_NAME, &fops);

if (Major < 0){
    printk(KERN_ALERT "I have failed to load!\n");
    return Major;
}

printk (KERN_ALERT "I was assigned major number %d\n" , Major);
printk (KERN_ALERT "Please create device with name  \n mknod /dev/%s c %d 0 \n" ,DEVICE_NAME , Major );
return 0;


}


int device_open(struct inode * inode, struct file *file){

//static int counter = 0;
if (Device_Open){
    return -EBUSY;

}
Device_Open++;

//sprintf(msg, "Good morning Dave, I was opened %d times", counter++);
msg_Ptr = msg;
try_module_get(THIS_MODULE);
return 0;
}



int device_release(struct inode  * inode, struct file *file){
    Device_Open--;

    module_put(THIS_MODULE);
    return 0;
}


ssize_t device_read(struct file  * file,  char * buffer, size_t length, loff_t *offset){
    int bytes_read = 0;
    if(*msg_Ptr == 0){
        return 0;
    }

    while(length && *msg_Ptr){
        put_user(* (msg_Ptr++), buffer++ );
        length--;
        bytes_read++;
}
        return bytes_read;



}



ssize_t device_write(struct file * file , const char * buffer, size_t length, loff_t *offset){

int count = 0;
memset (msg, 0, BUF_LEN);

while(length > 0){
copy_from_user(msg, buffer, BUF_LEN-1);
    count ++;
    length--;
    msg[BUF_LEN-1] = 0x00;


}

return count; /*ALWAYE RETURN SOMETHING!*/

}

