/*
 * ARM64 signal handling routines
 *
 * Copyright 2010-2013 André Hentschel
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef __aarch64__

#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/exception.h"
#include "ntdll_misc.h"
#include "wine/debug.h"
#include "ntsyscalls.h"

WINE_DEFAULT_DEBUG_CHANNEL(seh);
WINE_DECLARE_DEBUG_CHANNEL(relay);
WINE_DECLARE_DEBUG_CHANNEL(threadname);

/* layering violation: the setjmp buffer is defined in msvcrt, but used by RtlUnwindEx */
struct MSVCRT_JUMP_BUFFER
{
    unsigned __int64 Frame;
    unsigned __int64 Reserved;
    unsigned __int64 X19;
    unsigned __int64 X20;
    unsigned __int64 X21;
    unsigned __int64 X22;
    unsigned __int64 X23;
    unsigned __int64 X24;
    unsigned __int64 X25;
    unsigned __int64 X26;
    unsigned __int64 X27;
    unsigned __int64 X28;
    unsigned __int64 Fp;
    unsigned __int64 Lr;
    unsigned __int64 Sp;
    ULONG Fpcr;
    ULONG Fpsr;
    double D[8];
};

/*******************************************************************
 *         syscalls
 */
#define SYSCALL_ENTRY(id,name,args) __ASM_SYSCALL_FUNC( id, name )
ALL_SYSCALLS64
#undef SYSCALL_ENTRY


/**************************************************************************
 *		__chkstk (NTDLL.@)
 *
 * Supposed to touch all the stack pages, but we shouldn't need that.
 */
__ASM_GLOBAL_FUNC( __chkstk, "ret")


/***********************************************************************
 *		RtlCaptureContext (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( RtlCaptureContext,
                    "str xzr, [x0, #0x8]\n\t"        /* context->X0 */
                    "stp x1, x2, [x0, #0x10]\n\t"    /* context->X1,X2 */
                    "stp x3, x4, [x0, #0x20]\n\t"    /* context->X3,X4 */
                    "stp x5, x6, [x0, #0x30]\n\t"    /* context->X5,X6 */
                    "stp x7, x8, [x0, #0x40]\n\t"    /* context->X7,X8 */
                    "stp x9, x10, [x0, #0x50]\n\t"   /* context->X9,X10 */
                    "stp x11, x12, [x0, #0x60]\n\t"  /* context->X11,X12 */
                    "stp x13, x14, [x0, #0x70]\n\t"  /* context->X13,X14 */
                    "stp x15, x16, [x0, #0x80]\n\t"  /* context->X15,X16 */
                    "stp x17, x18, [x0, #0x90]\n\t"  /* context->X17,X18 */
                    "stp x19, x20, [x0, #0xa0]\n\t"  /* context->X19,X20 */
                    "stp x21, x22, [x0, #0xb0]\n\t"  /* context->X21,X22 */
                    "stp x23, x24, [x0, #0xc0]\n\t"  /* context->X23,X24 */
                    "stp x25, x26, [x0, #0xd0]\n\t"  /* context->X25,X26 */
                    "stp x27, x28, [x0, #0xe0]\n\t"  /* context->X27,X28 */
                    "stp x29, xzr, [x0, #0xf0]\n\t"  /* context->Fp,Lr */
                    "mov x1, sp\n\t"
                    "stp x1, x30, [x0, #0x100]\n\t"  /* context->Sp,Pc */
                    "stp q0,  q1,  [x0, #0x110]\n\t" /* context->V[0-1] */
                    "stp q2,  q3,  [x0, #0x130]\n\t" /* context->V[2-3] */
                    "stp q4,  q5,  [x0, #0x150]\n\t" /* context->V[4-5] */
                    "stp q6,  q7,  [x0, #0x170]\n\t" /* context->V[6-7] */
                    "stp q8,  q9,  [x0, #0x190]\n\t" /* context->V[8-9] */
                    "stp q10, q11, [x0, #0x1b0]\n\t" /* context->V[10-11] */
                    "stp q12, q13, [x0, #0x1d0]\n\t" /* context->V[12-13] */
                    "stp q14, q15, [x0, #0x1f0]\n\t" /* context->V[14-15] */
                    "stp q16, q17, [x0, #0x210]\n\t" /* context->V[16-17] */
                    "stp q18, q19, [x0, #0x230]\n\t" /* context->V[18-19] */
                    "stp q20, q21, [x0, #0x250]\n\t" /* context->V[20-21] */
                    "stp q22, q23, [x0, #0x270]\n\t" /* context->V[22-23] */
                    "stp q24, q25, [x0, #0x290]\n\t" /* context->V[24-25] */
                    "stp q26, q27, [x0, #0x2b0]\n\t" /* context->V[26-27] */
                    "stp q28, q29, [x0, #0x2d0]\n\t" /* context->V[28-29] */
                    "stp q30, q31, [x0, #0x2f0]\n\t" /* context->V[30-31] */
                    "mov w1, #0x400000\n\t"          /* CONTEXT_ARM64 */
                    "movk w1, #0x7\n\t"              /* CONTEXT_FULL */
                    "str w1, [x0]\n\t"               /* context->ContextFlags */
                    "mrs x1, NZCV\n\t"
                    "str w1, [x0, #0x4]\n\t"         /* context->Cpsr */
                    "mrs x1, FPCR\n\t"
                    "str w1, [x0, #0x310]\n\t"       /* context->Fpcr */
                    "mrs x1, FPSR\n\t"
                    "str w1, [x0, #0x314]\n\t"       /* context->Fpsr */
                    "ret" )

NTSTATUS WINAPI dispatch_exception( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    NTSTATUS status;
    DWORD c;

    TRACE( "code=%lx flags=%lx addr=%p pc=%016I64x\n",
           rec->ExceptionCode, rec->ExceptionFlags, rec->ExceptionAddress, context->Pc );
    for (c = 0; c < rec->NumberParameters; c++)
        TRACE( " info[%ld]=%016I64x\n", c, rec->ExceptionInformation[c] );

    if (rec->ExceptionCode == EXCEPTION_WINE_STUB)
    {
        if (rec->ExceptionInformation[1] >> 16)
            MESSAGE( "wine: Call from %p to unimplemented function %s.%s, aborting\n",
                     rec->ExceptionAddress,
                     (char*)rec->ExceptionInformation[0], (char*)rec->ExceptionInformation[1] );
        else
            MESSAGE( "wine: Call from %p to unimplemented function %s.%Id, aborting\n",
                     rec->ExceptionAddress,
                     (char*)rec->ExceptionInformation[0], rec->ExceptionInformation[1] );
    }
    else if (rec->ExceptionCode == EXCEPTION_WINE_NAME_THREAD && rec->ExceptionInformation[0] == 0x1000)
    {
        if ((DWORD)rec->ExceptionInformation[2] == -1 || (DWORD)rec->ExceptionInformation[2] == GetCurrentThreadId())
            WARN_(threadname)( "Thread renamed to %s\n", debugstr_a((char *)rec->ExceptionInformation[1]) );
        else
            WARN_(threadname)( "Thread ID %04lx renamed to %s\n", (DWORD)rec->ExceptionInformation[2],
                               debugstr_a((char *)rec->ExceptionInformation[1]) );

        set_native_thread_name((DWORD)rec->ExceptionInformation[2], (char *)rec->ExceptionInformation[1]);
    }
    else if (rec->ExceptionCode == DBG_PRINTEXCEPTION_C)
    {
        WARN( "%s\n", debugstr_an((char *)rec->ExceptionInformation[1], rec->ExceptionInformation[0] - 1) );
    }
    else if (rec->ExceptionCode == DBG_PRINTEXCEPTION_WIDE_C)
    {
        WARN( "%s\n", debugstr_wn((WCHAR *)rec->ExceptionInformation[1], rec->ExceptionInformation[0] - 1) );
    }
    else
    {
        if (rec->ExceptionCode == STATUS_ASSERTION_FAILURE)
            ERR( "%s exception (code=%lx) raised\n", debugstr_exception_code(rec->ExceptionCode), rec->ExceptionCode );
        else
            WARN( "%s exception (code=%lx) raised\n", debugstr_exception_code(rec->ExceptionCode), rec->ExceptionCode );

        context_trace_gprs( context );
    }

    if (call_vectored_handlers( rec, context ) == EXCEPTION_CONTINUE_EXECUTION)
        NtContinue( context, FALSE );

    if ((status = call_stack_handlers( rec, context )) == STATUS_SUCCESS)
        NtContinue( context, FALSE );

    if (status != STATUS_UNHANDLED_EXCEPTION) RtlRaiseStatus( status );
    return NtRaiseException( rec, context, FALSE );
}

// TODO: perhaps use unwind op for clearing flag
/*******************************************************************
 *		KiUserExceptionDispatcher (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( KiUserExceptionDispatcher,
                   __ASM_SEH(".seh_context\n\t")
                   __ASM_SEH(".seh_endprologue\n\t")
                   "adr x16, " __ASM_NAME("pWow64PrepareForException") "\n\t"
                   "ldr x16, [x16]\n\t"
                   "cbz x16, 1f\n\t"
                   "add x0, sp, #0x390\n\t"     /* rec (context + 1) */
                   "mov x1, sp\n\t"             /* context */
                   "blr x16\n"
                   "1:\tadd x0, sp, #0x390\n\t" /* rec (context + 1) */
                   "mov x1, sp\n\t"             /* context */
                   "bl " __ASM_NAME("dispatch_exception") "\n\t"
                   "brk #1" )


/*******************************************************************
 *		KiUserApcDispatcher (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( KiUserApcDispatcher,
                   __ASM_SEH(".seh_context\n\t")
                   "nop\n\t"
                   __ASM_SEH(".seh_stackalloc 0x30\n\t")
                   __ASM_SEH(".seh_endprologue\n\t")
                   "ldp x16, x0, [sp]\n\t"        /* func, arg1 */
                   "ldp x1, x2, [sp, #0x10]\n\t"  /* arg2, arg3 */
                   "add x3, sp, #0x30\n\t"        /* context (FIXME) */
                   "blr x16\n\t"
                   "add x0, sp, #0x30\n\t"        /* context */
                   "ldr w1, [sp, #0x20]\n\t"      /* alertable */
                   "bl " __ASM_NAME("NtContinue") "\n\t"
                   "brk #1" )


/*******************************************************************
 *		KiUserCallbackDispatcher (NTDLL.@)
 */
void WINAPI dispatch_callback( void *args, ULONG len, ULONG id )
{
    NTSTATUS status;

    __TRY
    {
        NTSTATUS (WINAPI *func)(void *, ULONG) = ((void **)NtCurrentTeb()->Peb->KernelCallbackTable)[id];
        status = NtCallbackReturn( NULL, 0, func( args, len ));
    }
    __EXCEPT_ALL
    {
        ERR_(seh)( "ignoring exception\n" );
        status = NtCallbackReturn( 0, 0, 0 );
    }
    __ENDTRY

    RtlRaiseStatus( status );
}
__ASM_GLOBAL_FUNC( KiUserCallbackDispatcher,
                   __ASM_SEH(".seh_pushframe\n\t")
                   "nop\n\t"
                   __ASM_SEH(".seh_stackalloc 0x20\n\t")
                   "nop\n\t"
                   __ASM_SEH(".seh_save_reg lr, 0x18\n\t")
                   __ASM_SEH(".seh_endprologue\n\t")
                   "ldr x0, [sp]\n\t"             /* args */
                   "ldp w1, w2, [sp, #0x08]\n\t"  /* len, id */
                   "bl " __ASM_NAME("dispatch_callback") "\n\t"
                   "brk #1" )

/**********************************************************************
 *              RtlVirtualUnwind   (NTDLL.@)
 */
PVOID WINAPI RtlVirtualUnwind( ULONG type, ULONG_PTR base, ULONG_PTR pc,
                               RUNTIME_FUNCTION *func, CONTEXT *context,
                               PVOID *handler_data, ULONG_PTR *frame_ret,
                               KNONVOLATILE_CONTEXT_POINTERS *ctx_ptr )
{
    return virtual_unwind_arm64( type, base, pc, func, context, handler_data, frame_ret, ctx_ptr );
}

/**********************************************************************
 *           call_consolidate_callback
 *
 * Wrapper function to call a consolidate callback from a fake frame.
 * If the callback executes RtlUnwindEx (like for example done in C++ handlers),
 * we have to skip all frames which were already processed. To do that we
 * trick the unwinding functions into thinking the call came from somewhere
 * else. All CFI instructions are either DW_CFA_def_cfa_expression or
 * DW_CFA_expression, and the expressions have the following format:
 *
 * DW_OP_breg31; sleb128 <OFFSET>       | Load x31 + struct member offset
 * [DW_OP_deref]                        | Dereference, only for CFA
 */
__ASM_GLOBAL_FUNC( call_consolidate_callback,
                   "stp x29, x30, [sp, #-0x30]!\n\t"
                   __ASM_CFI(".cfi_def_cfa_offset 48\n\t")
                   __ASM_CFI(".cfi_offset 29, -48\n\t")
                   __ASM_CFI(".cfi_offset 30, -40\n\t")
                   __ASM_SEH(".seh_nop\n\t")
                   "stp x1,  x2,  [sp, #0x10]\n\t"
                   __ASM_SEH(".seh_nop\n\t")
                   "str x18,      [sp, #0x20]\n\t"
                   __ASM_SEH(".seh_nop\n\t")
                   "mov x29, sp\n\t"
                   __ASM_CFI(".cfi_def_cfa_register 29\n\t")
                   __ASM_SEH(".seh_nop\n\t")
                   __ASM_CFI(".cfi_remember_state\n\t")
                   /* Memcpy the context onto the stack */
                   "sub sp, sp, #0x390\n\t"
                   __ASM_SEH(".seh_nop\n\t")
                   "mov x1,  x0\n\t"
                   __ASM_SEH(".seh_nop\n\t")
                   "mov x0,  sp\n\t"
                   __ASM_SEH(".seh_nop\n\t")
                   "mov x2,  #0x390\n\t"
                   __ASM_SEH(".seh_nop\n\t")
                   "bl " __ASM_NAME("memcpy") "\n\t"
                   __ASM_CFI(".cfi_def_cfa 31, 0\n\t")
                   __ASM_CFI(".cfi_escape 0x0f,0x04,0x8f,0x80,0x02,0x06\n\t") /* CFA, DW_OP_breg31 + 0x100, DW_OP_deref */
                   __ASM_CFI(".cfi_escape 0x10,0x13,0x03,0x8f,0xa0,0x01\n\t") /* x19, DW_OP_breg31 + 0xA0 */
                   __ASM_CFI(".cfi_escape 0x10,0x14,0x03,0x8f,0xa8,0x01\n\t") /* x20 */
                   __ASM_CFI(".cfi_escape 0x10,0x15,0x03,0x8f,0xb0,0x01\n\t") /* x21 */
                   __ASM_CFI(".cfi_escape 0x10,0x16,0x03,0x8f,0xb8,0x01\n\t") /* x22 */
                   __ASM_CFI(".cfi_escape 0x10,0x17,0x03,0x8f,0xc0,0x01\n\t") /* x23 */
                   __ASM_CFI(".cfi_escape 0x10,0x18,0x03,0x8f,0xc8,0x01\n\t") /* x24 */
                   __ASM_CFI(".cfi_escape 0x10,0x19,0x03,0x8f,0xd0,0x01\n\t") /* x25 */
                   __ASM_CFI(".cfi_escape 0x10,0x1a,0x03,0x8f,0xd8,0x01\n\t") /* x26 */
                   __ASM_CFI(".cfi_escape 0x10,0x1b,0x03,0x8f,0xe0,0x01\n\t") /* x27 */
                   __ASM_CFI(".cfi_escape 0x10,0x1c,0x03,0x8f,0xe8,0x01\n\t") /* x28 */
                   __ASM_CFI(".cfi_escape 0x10,0x1d,0x03,0x8f,0xf0,0x01\n\t") /* x29 */
                   __ASM_CFI(".cfi_escape 0x10,0x1e,0x03,0x8f,0xf8,0x01\n\t") /* x30 */
                   __ASM_CFI(".cfi_escape 0x10,0x48,0x03,0x8f,0x90,0x03\n\t") /* d8  */
                   __ASM_CFI(".cfi_escape 0x10,0x49,0x03,0x8f,0x98,0x03\n\t") /* d9  */
                   __ASM_CFI(".cfi_escape 0x10,0x4a,0x03,0x8f,0xa0,0x03\n\t") /* d10 */
                   __ASM_CFI(".cfi_escape 0x10,0x4b,0x03,0x8f,0xa8,0x03\n\t") /* d11 */
                   __ASM_CFI(".cfi_escape 0x10,0x4c,0x03,0x8f,0xb0,0x03\n\t") /* d12 */
                   __ASM_CFI(".cfi_escape 0x10,0x4d,0x03,0x8f,0xb8,0x03\n\t") /* d13 */
                   __ASM_CFI(".cfi_escape 0x10,0x4e,0x03,0x8f,0xc0,0x03\n\t") /* d14 */
                   __ASM_CFI(".cfi_escape 0x10,0x4f,0x03,0x8f,0xc8,0x03\n\t") /* d15 */
                   __ASM_SEH(".seh_context\n\t")
                   __ASM_SEH(".seh_endprologue\n\t")
                   "ldp x1,  x2,  [x29, #0x10]\n\t"
                   "ldr x18,      [x29, #0x20]\n\t"
                   "mov x0,  x2\n\t"
                   "blr x1\n\t"
                   "mov sp,  x29\n\t"
                   __ASM_CFI(".cfi_restore_state\n\t")
                   "ldp x29, x30, [sp], #48\n\t"
                   __ASM_CFI(".cfi_restore 30\n\t")
                   __ASM_CFI(".cfi_restore 29\n\t")
                   __ASM_CFI(".cfi_def_cfa 31, 0\n\t")
                   "ret")

void context_restore_from_jmpbuf( CONTEXT *context, void *buf )
{
    struct MSVCRT_JUMP_BUFFER *jmp = (struct MSVCRT_JUMP_BUFFER *)buf;
    int i;

    context->X19  = jmp->X19;
    context->X20  = jmp->X20;
    context->X21  = jmp->X21;
    context->X22  = jmp->X22;
    context->X23  = jmp->X23;
    context->X24  = jmp->X24;
    context->X25  = jmp->X25;
    context->X26  = jmp->X26;
    context->X27  = jmp->X27;
    context->X28  = jmp->X28;
    context->Fp   = jmp->Fp;
    context->Lr   = jmp->Lr;
    context->Sp   = jmp->Sp;
    context->Fpcr = jmp->Fpcr;
    context->Fpsr = jmp->Fpsr;

    for (i = 0; i < 8; i++)
        context->V[8+i].D[0] = jmp->D[i];
}

void context_trace_gprs( CONTEXT *context )
{
    TRACE("  x0=%016I64x  x1=%016I64x  x2=%016I64x  x3=%016I64x\n",
          context->X0, context->X1, context->X2, context->X3 );
    TRACE("  x4=%016I64x  x5=%016I64x  x6=%016I64x  x7=%016I64x\n",
          context->X4, context->X5, context->X6, context->X7 );
    TRACE("  x8=%016I64x  x9=%016I64x x10=%016I64x x11=%016I64x\n",
          context->X8, context->X9, context->X10, context->X11 );
    TRACE(" x12=%016I64x x13=%016I64x x14=%016I64x x15=%016I64x\n",
          context->X12, context->X13, context->X14, context->X15 );
    TRACE(" x16=%016I64x x17=%016I64x x18=%016I64x x19=%016I64x\n",
          context->X16, context->X17, context->X18, context->X19 );
    TRACE(" x20=%016I64x x21=%016I64x x22=%016I64x x23=%016I64x\n",
          context->X20, context->X21, context->X22, context->X23 );
    TRACE(" x24=%016I64x x25=%016I64x x26=%016I64x x27=%016I64x\n",
          context->X24, context->X25, context->X26, context->X27 );
    TRACE(" x28=%016I64x  fp=%016I64x  lr=%016I64x  sp=%016I64x\n",
          context->X28, context->Fp, context->Lr, context->Sp );
}

// TODO: vregs should be saved here?
__ASM_GLOBAL_FUNC( __C_ExecuteExceptionFilter,
                   "stp x29, x30, [sp, #-96]!\n\t"
                   __ASM_SEH(".seh_save_fplr_x 96\n\t")
                   "stp x19, x20, [sp, #16]\n\t"
                   __ASM_SEH(".seh_save_regp x19, 16\n\t")
                   "stp x21, x22, [sp, #32]\n\t"
                   __ASM_SEH(".seh_save_regp x21, 32\n\t")
                   "stp x23, x24, [sp, #48]\n\t"
                   __ASM_SEH(".seh_save_regp x23, 48\n\t")
                   "stp x25, x26, [sp, #64]\n\t"
                   __ASM_SEH(".seh_save_regp x25, 64\n\t")
                   "stp x27, x28, [sp, #80]\n\t"
                   __ASM_SEH(".seh_save_regp x27, 80\n\t")
                   "mov x29, sp\n\t"
                   __ASM_SEH(".seh_set_fp\n\t")
                   __ASM_SEH(".seh_endprologue\n\t")

                   __ASM_CFI(".cfi_def_cfa x29, 96\n\t")
                   __ASM_CFI(".cfi_offset x29, -96\n\t")
                   __ASM_CFI(".cfi_offset x30, -88\n\t")
                   __ASM_CFI(".cfi_offset x19, -80\n\t")
                   __ASM_CFI(".cfi_offset x20, -72\n\t")
                   __ASM_CFI(".cfi_offset x21, -64\n\t")
                   __ASM_CFI(".cfi_offset x22, -56\n\t")
                   __ASM_CFI(".cfi_offset x23, -48\n\t")
                   __ASM_CFI(".cfi_offset x24, -40\n\t")
                   __ASM_CFI(".cfi_offset x25, -32\n\t")
                   __ASM_CFI(".cfi_offset x26, -24\n\t")
                   __ASM_CFI(".cfi_offset x27, -16\n\t")
                   __ASM_CFI(".cfi_offset x28, -8\n\t")

                   "ldp x19, x20, [x3, #0]\n\t"
                   "ldp x21, x22, [x3, #16]\n\t"
                   "ldp x23, x24, [x3, #32]\n\t"
                   "ldp x25, x26, [x3, #48]\n\t"
                   "ldp x27, x28, [x3, #64]\n\t"
                   /* Overwrite the frame parameter with Fp from the
                    * nonvolatile regs */
                   "ldr x1, [x3, #80]\n\t"
                   "blr x2\n\t"
                   "ldp x19, x20, [sp, #16]\n\t"
                   "ldp x21, x22, [sp, #32]\n\t"
                   "ldp x23, x24, [sp, #48]\n\t"
                   "ldp x25, x26, [sp, #64]\n\t"
                   "ldp x27, x28, [sp, #80]\n\t"
                   "ldp x29, x30, [sp], #96\n\t"
                   "ret")

/* This is, implementation wise, identical to __C_ExecuteExceptionFilter. */
__ASM_GLOBAL_FUNC( __C_ExecuteTerminationHandler,
                   "b " __ASM_NAME("__C_ExecuteExceptionFilter") "\n\t");

/***********************************************************************
 *		RtlRaiseException (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( RtlRaiseException,
                   "sub sp, sp, #0x3b0\n\t" /* 0x390 (context) + 0x20 */
                   "stp x29, x30, [sp]\n\t"
                   __ASM_SEH(".seh_stackalloc 0x3b0\n\t")
                   __ASM_SEH(".seh_save_fplr 0\n\t")
                   __ASM_SEH(".seh_endprologue\n\t")
                   __ASM_CFI(".cfi_def_cfa x29, 944\n\t")
                   __ASM_CFI(".cfi_offset x30, -936\n\t")
                   __ASM_CFI(".cfi_offset x29, -944\n\t")
                   "mov x29, sp\n\t"
                   "str x0,  [sp, #0x10]\n\t"
                   "add x0,  sp, #0x20\n\t"
                   "bl " __ASM_NAME("RtlCaptureContext") "\n\t"
                   "add x1,  sp, #0x20\n\t"      /* context pointer */
                   "add x2,  sp, #0x3b0\n\t"     /* orig stack pointer */
                   "str x2,  [x1, #0x100]\n\t"   /* context->Sp */
                   "ldr x0,  [sp, #0x10]\n\t"    /* original first parameter */
                   "str x0,  [x1, #0x08]\n\t"    /* context->X0 */
                   "ldp x4, x5, [sp]\n\t"        /* frame pointer, return address */
                   "stp x4, x5, [x1, #0xf0]\n\t" /* context->Fp, Lr */
                   "str  x5, [x1, #0x108]\n\t"   /* context->Pc */
                   "str  x5, [x0, #0x10]\n\t"    /* rec->ExceptionAddress */
                   "ldr x3, [x18, #0x60]\n\t"    /* peb */
                   "ldrb w2, [x3, #2]\n\t"       /* peb->BeingDebugged */
                   "cbnz w2, 1f\n\t"
                   "bl " __ASM_NAME("dispatch_exception") "\n"
                   "1:\tmov  x2, #1\n\t"
                   "bl " __ASM_NAME("NtRaiseException") "\n\t"
                   "bl " __ASM_NAME("RtlRaiseStatus") /* does not return */ );

/***********************************************************************
 *           RtlUserThreadStart (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( RtlUserThreadStart,
                   "stp x29, x30, [sp, #-16]!\n\t"
                   __ASM_SEH(".seh_save_fplr_x 16\n\t")
                   __ASM_SEH(".seh_endprologue\n\t")
                   "adr x8, " __ASM_NAME("pBaseThreadInitThunk") "\n\t"
                   "ldr x8, [x8]\n\t"
                   "mov x2, x1\n\t"
                   "mov x1, x0\n\t"
                   "mov x0, #0\n\t"
                   "blr x8\n\t"
                   __ASM_SEH(".seh_handler " __ASM_NAME("call_unhandled_exception_handler") ", @except") )

/******************************************************************
 *		LdrInitializeThunk (NTDLL.@)
 */
void WINAPI LdrInitializeThunk( CONTEXT *context, ULONG_PTR unk2, ULONG_PTR unk3, ULONG_PTR unk4 )
{
    loader_init( context, (void **)&context->X0 );
    TRACE_(relay)( "\1Starting thread proc %p (arg=%p)\n", (void *)context->X0, (void *)context->X1 );
    NtContinue( context, TRUE );
}

/**********************************************************************
 *              DbgBreakPoint   (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( DbgBreakPoint, "brk #0xf000; ret"
                    "\n\tnop; nop; nop; nop; nop; nop; nop; nop"
                    "\n\tnop; nop; nop; nop; nop; nop" );

/**********************************************************************
 *              DbgUserBreakPoint   (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( DbgUserBreakPoint, "brk #0xf000; ret"
                    "\n\tnop; nop; nop; nop; nop; nop; nop; nop"
                    "\n\tnop; nop; nop; nop; nop; nop" );

#endif  /* __aarch64__ */
