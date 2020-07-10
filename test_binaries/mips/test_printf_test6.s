	.file	1 "test_printf.c"
	.section .mdebug.abi32
	.previous
	.nan	legacy
	.module	fp=xx
	.module	nooddspreg
	.abicalls
	.text
	.rdata
	.align	2
added_data_rw: # patch is here
    .ascii "CCCCC\0x00"
    .align  2
$LC0:
	.ascii	"Hello\000"
	.align	2
$LC1:
	.ascii	"%s\000"
	.text
	.align	2
	.globl	main
	.set	nomips16
	.set	nomicromips
	.ent	main
	.type	main, @function
main:
	.frame	$fp,32,$31		# vars= 0, regs= 2/0, args= 16, gp= 8
	.mask	0xc0000000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	addiu	$sp,$sp,-32
	sw	$31,28($sp)
	sw	$fp,24($sp)
	move	$fp,$sp
	lui	$28,%hi(__gnu_local_gp)
	addiu	$28,$28,%lo(__gnu_local_gp)
	.cprestore	16
	lui	$2,%hi($LC0)
	addiu	$5,$2,%lo($LC0)
	lui	$2,%hi($LC1)
	addiu	$4,$2,%lo($LC1)
	lw	$2,%call16(printf)($28)
	move	$25,$2
	.reloc	1f,R_MIPS_JALR,printf
1:	jalr	$25
	nop

	# patch is here
	lw	$28,16($fp)
	move	$2,$0
	
    li $t0, 0x41
    li $t1, 0x0
    li $t2, 0x5
    lui	$v0,%hi(added_data_rw)
	addiu	$v1,$v0,%lo(added_data_rw)
    loop:
        beq $t1, $t2, exit
        sb $t0, 0($v1) # something is wrong here
        addiu $v1, $v1, 1
        addiu $t1, $t1, 1
        j loop
    exit:
        lui	$2,%hi(added_data_rw)
	    addiu	$4,$2,%lo(added_data_rw)
	    lw	$2,%call16(printf)($28)
        move	$25,$2
	    jalr	$25
    # patch ends here
    
	lw	$28,16($fp)
	move	$2,$0
	move	$sp,$fp
	lw	$31,28($sp)
	lw	$fp,24($sp)
	addiu	$sp,$sp,32
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	main
	.size	main, .-main
	.ident	"GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0"
