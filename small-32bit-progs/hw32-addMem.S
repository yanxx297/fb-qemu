.data
.text
	.globl	_start
_start:	
	add	(%eax), %eax
	jmp	exit

	# exit(0)
exit:
	mov	$1, %eax
	mov	$0, %ebx
	int	$0x80
