#ifndef HOOK_FUNCTION_PTR
#define HOOK_FUNCTION_PTR

/* copy from fs/exec.c */
struct user_arg_ptr {
	union {
		const char __user *const __user *native;
	} ptr;
};


#define SYS_CALL_TABLE_ADDR \
(unsigned long*)0xc16390a0

#define DO_EXECVE_ADDR \
(int (*)(const char *, const char __user *const __user *, const char __user *const __user *))0xc116b330

#define DO_EXECVE_COMMON_ADDR \
(int (*)(const char *, struct user_arg_ptr argv, struct user_arg_ptr envp))0xc116b080

#define PUTNAME_ADDR \
(void (*)(struct filename *))0xc1171cc0

#endif