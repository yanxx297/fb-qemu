.data
msg:
	.ascii "Hello, world!\n"
.text
	.globl	_start
_start:	
	# write(1, "Hello, world!\n", 14)
	mov	$4, %eax
	mov	$1, %ebx
	mov	$msg, %ecx
	mov	$14, %edx
	int	$0x80

	# exit(0)
	mov	$1, %eax
	mov	$0, %ebx
	int	$0x80
