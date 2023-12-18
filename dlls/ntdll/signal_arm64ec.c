/*
 * ARM64EC signal handling routines
 *
 * Copyright 1999, 2005, 2023 Alexandre Julliard
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

#ifdef __arm64ec__

#include <stdlib.h>
#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/exception.h"
#include "wine/list.h"
#include "ntdll_misc.h"
#include "wine/debug.h"
#include "ntsyscalls.h"

WINE_DEFAULT_DEBUG_CHANNEL(unwind);
WINE_DECLARE_DEBUG_CHANNEL(seh);
WINE_DECLARE_DEBUG_CHANNEL(relay);

/* layering violation: the setjmp buffer is defined in msvcrt, but used by RtlUnwindEx */
struct MSVCRT_JUMP_BUFFER
{
    ULONG64 Frame;
    ULONG64 Rbx;
    ULONG64 Rsp;
    ULONG64 Rbp;
    ULONG64 Rsi;
    ULONG64 Rdi;
    ULONG64 R12;
    ULONG64 R13;
    ULONG64 R14;
    ULONG64 R15;
    ULONG64 Rip;
    ULONG  MxCsr;
    USHORT FpCsr;
    USHORT Spare;
    M128A   Xmm6;
    M128A   Xmm7;
    M128A   Xmm8;
    M128A   Xmm9;
    M128A   Xmm10;
    M128A   Xmm11;
    M128A   Xmm12;
    M128A   Xmm13;
    M128A   Xmm14;
    M128A   Xmm15;
};

__declspec(naked) void capture_arm64_context( ARM64_NT_CONTEXT *context )
{
    asm( "str xzr, [x0, #0x8]\n\t"        /* context->X0 */
         "stp x1,  x2,  [x0, #0x10]\n\t"  /* context->X1,X2 */
         "stp x3,  x4,  [x0, #0x20]\n\t"  /* context->X3,X4 */
         "stp x5,  x6,  [x0, #0x30]\n\t"  /* context->X5,X6 */
         "stp x7,  x8,  [x0, #0x40]\n\t"  /* context->X7,X8 */
         "stp x9,  x10, [x0, #0x50]\n\t"  /* context->X9,X10 */
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
         "mov x1,  sp\n\t"
         "stp x1,  x30, [x0, #0x100]\n\t" /* context->Sp,Pc */
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
         "ret"
    );
}



static ULONG ctx_flags_x64_to_arm( ULONG flags )
{
    ULONG ret = CONTEXT_ARM64;

    flags &= ~CONTEXT_AMD64;
    if (flags & CONTEXT_AMD64_CONTROL) ret |= CONTEXT_ARM64_CONTROL;
    if (flags & CONTEXT_AMD64_INTEGER) ret |= CONTEXT_ARM64_INTEGER;
    if (flags & CONTEXT_AMD64_FLOATING_POINT) ret |= CONTEXT_ARM64_FLOATING_POINT;
    if (flags & CONTEXT_AMD64_UNWOUND_TO_CALL) ret |= CONTEXT_ARM64_UNWOUND_TO_CALL;
    return ret;
}

static ULONG ctx_flags_arm_to_x64( ULONG flags )
{
    ULONG ret = CONTEXT_AMD64;

    flags &= ~CONTEXT_ARM64;
    if (flags & CONTEXT_ARM64_CONTROL) ret |= CONTEXT_AMD64_CONTROL;
    if (flags & CONTEXT_ARM64_INTEGER) ret |= CONTEXT_AMD64_INTEGER;
    if (flags & CONTEXT_ARM64_FLOATING_POINT) ret |= CONTEXT_AMD64_FLOATING_POINT;
    if (flags & CONTEXT_ARM64_UNWOUND_TO_CALL) ret |= CONTEXT_AMD64_UNWOUND_TO_CALL;
    return ret;
}

static UINT eflags_to_cpsr( UINT eflags )
{
    UINT ret = 0;

    if (eflags & 0x0001) ret |= 0x20000000;  /* carry */
    if (eflags & 0x0040) ret |= 0x40000000;  /* zero */
    if (eflags & 0x0080) ret |= 0x80000000;  /* negative */
    if (eflags & 0x0800) ret |= 0x10000000;  /* overflow */
    return ret;
}

static UINT cpsr_to_eflags( UINT cpsr )
{
    UINT ret = 0;

    if (cpsr & 0x10000000) ret |= 0x0800;  /* overflow */
    if (cpsr & 0x20000000) ret |= 0x0001;  /* carry */
    if (cpsr & 0x40000000) ret |= 0x0040;  /* zero */
    if (cpsr & 0x80000000) ret |= 0x0080;  /* negative */
    return ret;
}

static UINT64 mxcsr_to_fpcsr( UINT mxcsr )
{
    UINT fpcr = 0, fpsr = 0;

    if (mxcsr & 0x0001) fpsr |= 0x0001;    /* invalid operation */
    if (mxcsr & 0x0002) fpsr |= 0x0080;    /* denormal */
    if (mxcsr & 0x0004) fpsr |= 0x0002;    /* zero-divide */
    if (mxcsr & 0x0008) fpsr |= 0x0004;    /* overflow */
    if (mxcsr & 0x0010) fpsr |= 0x0008;    /* underflow */
    if (mxcsr & 0x0020) fpsr |= 0x0010;    /* precision */

    if (mxcsr & 0x0040) fpcr |= 0x0001;    /* denormals are zero */
    if (mxcsr & 0x0080) fpcr |= 0x0100;    /* invalid operation mask */
    if (mxcsr & 0x0100) fpcr |= 0x8000;    /* denormal mask */
    if (mxcsr & 0x0200) fpcr |= 0x0200;    /* zero-divide mask */
    if (mxcsr & 0x0400) fpcr |= 0x0400;    /* overflow mask */
    if (mxcsr & 0x0800) fpcr |= 0x0800;    /* underflow mask */
    if (mxcsr & 0x1000) fpcr |= 0x1000;    /* precision mask */
    if (mxcsr & 0x2000) fpcr |= 0x800000;  /* round down */
    if (mxcsr & 0x4000) fpcr |= 0x400000;  /* round up */
    if (mxcsr & 0x8000) fpcr |= 0x1000000; /* flush to zero */
    return fpcr | ((UINT64)fpsr << 32);
}

static UINT fpcsr_to_mxcsr( UINT fpcr, UINT fpsr )
{
    UINT ret = 0;

    if (fpsr & 0x0001) ret |= 0x0001;      /* invalid operation */
    if (fpsr & 0x0002) ret |= 0x0004;      /* zero-divide */
    if (fpsr & 0x0004) ret |= 0x0008;      /* overflow */
    if (fpsr & 0x0008) ret |= 0x0010;      /* underflow */
    if (fpsr & 0x0010) ret |= 0x0020;      /* precision */
    if (fpsr & 0x0080) ret |= 0x0002;      /* denormal */

    if (fpcr & 0x0000001) ret |= 0x0040;   /* denormals are zero */
    if (fpcr & 0x0000100) ret |= 0x0080;   /* invalid operation mask */
    if (fpcr & 0x0000200) ret |= 0x0200;   /* zero-divide mask */
    if (fpcr & 0x0000400) ret |= 0x0400;   /* overflow mask */
    if (fpcr & 0x0000800) ret |= 0x0800;   /* underflow mask */
    if (fpcr & 0x0001000) ret |= 0x1000;   /* precision mask */
    if (fpcr & 0x0008000) ret |= 0x0100;   /* denormal mask */
    if (fpcr & 0x0400000) ret |= 0x4000;   /* round up */
    if (fpcr & 0x0800000) ret |= 0x2000;   /* round down */
    if (fpcr & 0x1000000) ret |= 0x8000;   /* flush to zero */
    return ret;
}

static void context_x64_to_arm( ARM64_NT_CONTEXT *arm_ctx, const CONTEXT *ctx )
{
    ARM64EC_NT_CONTEXT *ec_ctx = (ARM64EC_NT_CONTEXT *)ctx;
    UINT64 fpcsr;

    arm_ctx->ContextFlags = ctx_flags_x64_to_arm( ec_ctx->ContextFlags );
    arm_ctx->Cpsr = eflags_to_cpsr( ec_ctx->AMD64_EFlags );
    arm_ctx->X0   = ec_ctx->X0;
    arm_ctx->X1   = ec_ctx->X1;
    arm_ctx->X2   = ec_ctx->X2;
    arm_ctx->X3   = ec_ctx->X3;
    arm_ctx->X4   = ec_ctx->X4;
    arm_ctx->X5   = ec_ctx->X5;
    arm_ctx->X6   = ec_ctx->X6;
    arm_ctx->X7   = ec_ctx->X7;
    arm_ctx->X8   = ec_ctx->X8;
    arm_ctx->X9   = ec_ctx->X9;
    arm_ctx->X10  = ec_ctx->X10;
    arm_ctx->X11  = ec_ctx->X11;
    arm_ctx->X12  = ec_ctx->X12;
    arm_ctx->X13  = 0;
    arm_ctx->X14  = 0;
    arm_ctx->X15  = ec_ctx->X15;
    arm_ctx->X16  = ec_ctx->X16_0 | ((DWORD64)ec_ctx->X16_1 << 16) | ((DWORD64)ec_ctx->X16_2 << 32) | ((DWORD64)ec_ctx->X16_3 << 48);
    arm_ctx->X17  = ec_ctx->X17_0 | ((DWORD64)ec_ctx->X17_1 << 16) | ((DWORD64)ec_ctx->X17_2 << 32) | ((DWORD64)ec_ctx->X17_3 << 48);
    arm_ctx->X18  = 0;
    arm_ctx->X19  = ec_ctx->X19;
    arm_ctx->X20  = ec_ctx->X20;
    arm_ctx->X21  = ec_ctx->X21;
    arm_ctx->X22  = ec_ctx->X22;
    arm_ctx->X23  = 0;
    arm_ctx->X24  = 0;
    arm_ctx->X25  = ec_ctx->X25;
    arm_ctx->X26  = ec_ctx->X26;
    arm_ctx->X27  = ec_ctx->X27;
    arm_ctx->X28  = 0;
    arm_ctx->Fp   = ec_ctx->Fp;
    arm_ctx->Lr   = ec_ctx->Lr;
    arm_ctx->Sp   = ec_ctx->Sp;
    arm_ctx->Pc   = ec_ctx->Pc;
    memcpy( arm_ctx->V, ec_ctx->V, 16 * sizeof(arm_ctx->V[0]) );
    memset( arm_ctx->V + 16, 0, sizeof(*arm_ctx) - offsetof( ARM64_NT_CONTEXT, V[16] ));
    fpcsr = mxcsr_to_fpcsr( ec_ctx->AMD64_MxCsr );
    arm_ctx->Fpcr = fpcsr;
    arm_ctx->Fpsr = fpcsr >> 32;
}

static void context_arm_to_x64( CONTEXT *ctx, const ARM64_NT_CONTEXT *arm_ctx )
{
    ARM64EC_NT_CONTEXT *ec_ctx = (ARM64EC_NT_CONTEXT *)ctx;

    memset( ec_ctx, 0, sizeof(*ec_ctx) );
    ec_ctx->ContextFlags = ctx_flags_arm_to_x64( arm_ctx->ContextFlags );
    ec_ctx->AMD64_SegCs  = 0x33;
    ec_ctx->AMD64_SegDs  = 0x2b;
    ec_ctx->AMD64_SegEs  = 0x2b;
    ec_ctx->AMD64_SegFs  = 0x53;
    ec_ctx->AMD64_SegGs  = 0x2b;
    ec_ctx->AMD64_SegSs  = 0x2b;
    ec_ctx->AMD64_EFlags = cpsr_to_eflags( arm_ctx->Cpsr );
    ec_ctx->AMD64_MxCsr  = ec_ctx->AMD64_MxCsr_copy = fpcsr_to_mxcsr( arm_ctx->Fpcr, arm_ctx->Fpsr );

    ec_ctx->X8    = arm_ctx->X8;
    ec_ctx->X0    = arm_ctx->X0;
    ec_ctx->X1    = arm_ctx->X1;
    ec_ctx->X27   = arm_ctx->X27;
    ec_ctx->Sp    = arm_ctx->Sp;
    ec_ctx->Fp    = arm_ctx->Fp;
    ec_ctx->X25   = arm_ctx->X25;
    ec_ctx->X26   = arm_ctx->X26;
    ec_ctx->X2    = arm_ctx->X2;
    ec_ctx->X3    = arm_ctx->X3;
    ec_ctx->X4    = arm_ctx->X4;
    ec_ctx->X5    = arm_ctx->X5;
    ec_ctx->X19   = arm_ctx->X19;
    ec_ctx->X20   = arm_ctx->X20;
    ec_ctx->X21   = arm_ctx->X21;
    ec_ctx->X22   = arm_ctx->X22;
    ec_ctx->Pc    = arm_ctx->Pc;
    ec_ctx->Lr    = arm_ctx->Lr;
    ec_ctx->X6    = arm_ctx->X6;
    ec_ctx->X7    = arm_ctx->X7;
    ec_ctx->X9    = arm_ctx->X9;
    ec_ctx->X10   = arm_ctx->X10;
    ec_ctx->X11   = arm_ctx->X11;
    ec_ctx->X12   = arm_ctx->X12;
    ec_ctx->X15   = arm_ctx->X15;
    ec_ctx->X16_0 = arm_ctx->X16;
    ec_ctx->X16_1 = arm_ctx->X16 >> 16;
    ec_ctx->X16_2 = arm_ctx->X16 >> 32;
    ec_ctx->X16_3 = arm_ctx->X16 >> 48;
    ec_ctx->X17_0 = arm_ctx->X17;
    ec_ctx->X17_1 = arm_ctx->X17 >> 16;
    ec_ctx->X17_2 = arm_ctx->X17 >> 32;
    ec_ctx->X17_3 = arm_ctx->X17 >> 48;

    memcpy( ec_ctx->V, arm_ctx->V, sizeof(ec_ctx->V) );
}

static BOOLEAN syscall_callback_begin( void *func )
{
    BOOLEAN *InSyscallCallback = &NtCurrentTeb()->ChpeV2CpuAreaInfo->InSyscallCallback;
    if (func && !*InSyscallCallback) {
        *InSyscallCallback = TRUE;
        return TRUE;
    }
    return FALSE;
}

static void syscall_callback_end(void)
{
    NtCurrentTeb()->ChpeV2CpuAreaInfo->InSyscallCallback = FALSE;
}

/*******************************************************************
 *         syscalls
 */
enum syscall_ids
{
#define SYSCALL_ENTRY(id,name,args) __id_##name = id,
ALL_SYSCALLS64
#undef SYSCALL_ENTRY
};

#define SYSCALL_API __attribute__((naked))

NTSTATUS SYSCALL_API NtAcceptConnectPort( HANDLE *handle, ULONG id, LPC_MESSAGE *msg, BOOLEAN accept,
                                          LPC_SECTION_WRITE *write, LPC_SECTION_READ *read )
{
    __ASM_SYSCALL_FUNC( __id_NtAcceptConnectPort );
}

NTSTATUS SYSCALL_API NtAccessCheck( PSECURITY_DESCRIPTOR descr, HANDLE token, ACCESS_MASK access,
                                    GENERIC_MAPPING *mapping, PRIVILEGE_SET *privs, ULONG *retlen,
                                    ULONG *access_granted, NTSTATUS *access_status )
{
    __ASM_SYSCALL_FUNC( __id_NtAccessCheck );
}

NTSTATUS SYSCALL_API NtAccessCheckAndAuditAlarm( UNICODE_STRING *subsystem, HANDLE handle,
                                                 UNICODE_STRING *typename, UNICODE_STRING *objectname,
                                                 PSECURITY_DESCRIPTOR descr, ACCESS_MASK access,
                                                 GENERIC_MAPPING *mapping, BOOLEAN creation,
                                                 ACCESS_MASK *access_granted, BOOLEAN *access_status,
                                                 BOOLEAN *onclose )
{
    __ASM_SYSCALL_FUNC( __id_NtAccessCheckAndAuditAlarm );
}

NTSTATUS SYSCALL_API NtAddAtom( const WCHAR *name, ULONG length, RTL_ATOM *atom )
{
    __ASM_SYSCALL_FUNC( __id_NtAddAtom );
}

NTSTATUS SYSCALL_API NtAdjustGroupsToken( HANDLE token, BOOLEAN reset, TOKEN_GROUPS *groups,
                                          ULONG length, TOKEN_GROUPS *prev, ULONG *retlen )
{
    __ASM_SYSCALL_FUNC( __id_NtAdjustGroupsToken );
}

NTSTATUS SYSCALL_API NtAdjustPrivilegesToken( HANDLE token, BOOLEAN disable, TOKEN_PRIVILEGES *privs,
                                              DWORD length, TOKEN_PRIVILEGES *prev, DWORD *retlen )
{
    __ASM_SYSCALL_FUNC( __id_NtAdjustPrivilegesToken );
}

NTSTATUS SYSCALL_API NtAlertResumeThread( HANDLE handle, ULONG *count )
{
    __ASM_SYSCALL_FUNC( __id_NtAlertResumeThread );
}

NTSTATUS SYSCALL_API NtAlertThread( HANDLE handle )
{
    __ASM_SYSCALL_FUNC( __id_NtAlertThread );
}

NTSTATUS SYSCALL_API NtAlertThreadByThreadId( HANDLE tid )
{
    __ASM_SYSCALL_FUNC( __id_NtAlertThreadByThreadId );
}

NTSTATUS SYSCALL_API NtAllocateLocallyUniqueId( LUID *luid )
{
    __ASM_SYSCALL_FUNC( __id_NtAllocateLocallyUniqueId );
}

NTSTATUS SYSCALL_API NtAllocateUuids( ULARGE_INTEGER *time, ULONG *delta, ULONG *sequence, UCHAR *seed )
{
    __ASM_SYSCALL_FUNC( __id_NtAllocateUuids );
}

static NTSTATUS SYSCALL_API syscall_NtAllocateVirtualMemory( HANDLE process, PVOID *ret,
                                                             ULONG_PTR zero_bits, SIZE_T *size_ptr,
                                                             ULONG type, ULONG protect )
{
    __ASM_SYSCALL_FUNC( __id_NtAllocateVirtualMemory );
}

NTSTATUS WINAPI NtAllocateVirtualMemory( HANDLE process, PVOID *ret, ULONG_PTR zero_bits,
                                         SIZE_T *size_ptr, ULONG type, ULONG protect )
{
    NTSTATUS status = syscall_NtAllocateVirtualMemory( process, ret, zero_bits, size_ptr, type,
                                                       protect );
    if (!status && RtlIsCurrentProcess( process ) &&
        syscall_callback_begin( arm64ec_callbacks.pNotifyMemoryAlloc ))
    {
        arm64ec_callbacks.pNotifyMemoryAlloc( *ret, *size_ptr, type, protect );
        syscall_callback_end();
    }

    return status;
}

static NTSTATUS SYSCALL_API syscall_NtAllocateVirtualMemoryEx( HANDLE process, PVOID *ret,
                                                               SIZE_T *size_ptr, ULONG type,
                                                               ULONG protect,
                                                               MEM_EXTENDED_PARAMETER *parameters,
                                                               ULONG count )
{
    __ASM_SYSCALL_FUNC( __id_NtAllocateVirtualMemoryEx );
}

NTSTATUS WINAPI NtAllocateVirtualMemoryEx( HANDLE process, PVOID *ret, SIZE_T *size_ptr, ULONG type,
                                           ULONG protect, MEM_EXTENDED_PARAMETER *parameters,
                                           ULONG count )
{
    NTSTATUS status = syscall_NtAllocateVirtualMemoryEx( process, ret, size_ptr, type, protect,
                                                             parameters, count );
    if (!status && RtlIsCurrentProcess( process ) &&
        syscall_callback_begin( arm64ec_callbacks.pNotifyMemoryAlloc ))
    {
        arm64ec_callbacks.pNotifyMemoryAlloc( *ret, *size_ptr, type, protect );
        syscall_callback_end();
    }

    return status;
}

NTSTATUS SYSCALL_API NtAreMappedFilesTheSame(PVOID addr1, PVOID addr2)
{
    __ASM_SYSCALL_FUNC( __id_NtAreMappedFilesTheSame );
}

NTSTATUS SYSCALL_API NtAssignProcessToJobObject( HANDLE job, HANDLE process )
{
    __ASM_SYSCALL_FUNC( __id_NtAssignProcessToJobObject );
}

NTSTATUS SYSCALL_API NtCallbackReturn( void *ret_ptr, ULONG ret_len, NTSTATUS status )
{
    __ASM_SYSCALL_FUNC( __id_NtCallbackReturn );
}

NTSTATUS SYSCALL_API NtCancelIoFile( HANDLE handle, IO_STATUS_BLOCK *io_status )
{
    __ASM_SYSCALL_FUNC( __id_NtCancelIoFile );
}

NTSTATUS SYSCALL_API NtCancelIoFileEx( HANDLE handle, IO_STATUS_BLOCK *io, IO_STATUS_BLOCK *io_status )
{
    __ASM_SYSCALL_FUNC( __id_NtCancelIoFileEx );
}

NTSTATUS SYSCALL_API NtCancelSynchronousIoFile( HANDLE handle, IO_STATUS_BLOCK *io,
                                                IO_STATUS_BLOCK *io_status )
{
    __ASM_SYSCALL_FUNC( __id_NtCancelSynchronousIoFile );
}

NTSTATUS SYSCALL_API NtCancelTimer( HANDLE handle, BOOLEAN *state )
{
    __ASM_SYSCALL_FUNC( __id_NtCancelTimer );
}

NTSTATUS SYSCALL_API NtClearEvent( HANDLE handle )
{
    __ASM_SYSCALL_FUNC( __id_NtClearEvent );
}

NTSTATUS SYSCALL_API NtClose( HANDLE handle )
{
    __ASM_SYSCALL_FUNC( __id_NtClose );
}

NTSTATUS SYSCALL_API NtCommitTransaction( HANDLE transaction, BOOLEAN wait )
{
    __ASM_SYSCALL_FUNC( __id_NtCommitTransaction );
}

NTSTATUS SYSCALL_API NtCompareObjects( HANDLE first, HANDLE second )
{
    __ASM_SYSCALL_FUNC( __id_NtCompareObjects );
}

NTSTATUS SYSCALL_API NtCompleteConnectPort( HANDLE handle )
{
    __ASM_SYSCALL_FUNC( __id_NtCompleteConnectPort );
}

NTSTATUS SYSCALL_API NtConnectPort( HANDLE *handle, UNICODE_STRING *name, SECURITY_QUALITY_OF_SERVICE *qos,
                                    LPC_SECTION_WRITE *write, LPC_SECTION_READ *read, ULONG *max_len,
                                    void *info, ULONG *info_len )
{
    __ASM_SYSCALL_FUNC( __id_NtConnectPort );
}

static NTSTATUS SYSCALL_API syscall_NtContinue( ARM64_NT_CONTEXT *context, BOOLEAN alertable )
{
    __ASM_SYSCALL_FUNC( __id_NtContinue );
}

NTSTATUS WINAPI NtContinue( CONTEXT *context, BOOLEAN alertable )
{
    ARM64_NT_CONTEXT arm_ctx;

    context_x64_to_arm( &arm_ctx, context );
    return syscall_NtContinue( &arm_ctx, alertable );
}

NTSTATUS SYSCALL_API NtCreateDebugObject( HANDLE *handle, ACCESS_MASK access,
                                          OBJECT_ATTRIBUTES *attr, ULONG flags )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateDebugObject );
}

NTSTATUS SYSCALL_API NtCreateDirectoryObject( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateDirectoryObject );
}

NTSTATUS SYSCALL_API NtCreateEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                    EVENT_TYPE type, BOOLEAN state )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateEvent );
}

NTSTATUS SYSCALL_API NtCreateFile( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                   IO_STATUS_BLOCK *io, LARGE_INTEGER *alloc_size,
                                   ULONG attributes, ULONG sharing, ULONG disposition,
                                   ULONG options, void *ea_buffer, ULONG ea_length )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateFile );
}

NTSTATUS SYSCALL_API NtCreateIoCompletion( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                           ULONG threads )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateIoCompletion );
}

NTSTATUS SYSCALL_API NtCreateJobObject( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateJobObject );
}

NTSTATUS SYSCALL_API NtCreateKey( HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                  ULONG index, const UNICODE_STRING *class, ULONG options, ULONG *dispos )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateKey );
}

NTSTATUS SYSCALL_API NtCreateKeyTransacted( HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                            ULONG index, const UNICODE_STRING *class, ULONG options,
                                            HANDLE transacted, ULONG *dispos )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateKeyTransacted );
}

NTSTATUS SYSCALL_API NtCreateKeyedEvent( HANDLE *handle, ACCESS_MASK access,
                                         const OBJECT_ATTRIBUTES *attr, ULONG flags )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateKeyedEvent );
}

NTSTATUS SYSCALL_API NtCreateLowBoxToken( HANDLE *token_handle, HANDLE token, ACCESS_MASK access,
                                          OBJECT_ATTRIBUTES *attr, SID *sid, ULONG count,
                                          SID_AND_ATTRIBUTES *capabilities, ULONG handle_count,
                                          HANDLE *handle )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateLowBoxToken );
}

NTSTATUS SYSCALL_API NtCreateMailslotFile( HANDLE *handle, ULONG access, OBJECT_ATTRIBUTES *attr,
                                           IO_STATUS_BLOCK *io, ULONG options, ULONG quota, ULONG msg_size,
                                           LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateMailslotFile );
}

NTSTATUS SYSCALL_API NtCreateMutant( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                     BOOLEAN owned )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateMutant );
}

NTSTATUS SYSCALL_API NtCreateNamedPipeFile( HANDLE *handle, ULONG access, OBJECT_ATTRIBUTES *attr,
                                            IO_STATUS_BLOCK *io, ULONG sharing, ULONG dispo, ULONG options,
                                            ULONG pipe_type, ULONG read_mode, ULONG completion_mode,
                                            ULONG max_inst, ULONG inbound_quota, ULONG outbound_quota,
                                            LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateNamedPipeFile );
}

NTSTATUS SYSCALL_API NtCreatePagingFile( UNICODE_STRING *name, LARGE_INTEGER *min_size,
                                         LARGE_INTEGER *max_size, LARGE_INTEGER *actual_size )
{
    __ASM_SYSCALL_FUNC( __id_NtCreatePagingFile );
}

NTSTATUS SYSCALL_API NtCreatePort( HANDLE *handle, OBJECT_ATTRIBUTES *attr, ULONG info_len,
                                   ULONG data_len, ULONG *reserved )
{
    __ASM_SYSCALL_FUNC( __id_NtCreatePort );
}

NTSTATUS SYSCALL_API NtCreateSection( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                      const LARGE_INTEGER *size, ULONG protect,
                                      ULONG sec_flags, HANDLE file )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateSection );
}

NTSTATUS SYSCALL_API NtCreateSemaphore( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                        LONG initial, LONG max )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateSemaphore );
}

NTSTATUS SYSCALL_API NtCreateSymbolicLinkObject( HANDLE *handle, ACCESS_MASK access,
                                                 OBJECT_ATTRIBUTES *attr, UNICODE_STRING *target )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateSymbolicLinkObject );
}

NTSTATUS SYSCALL_API NtCreateThread( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                     HANDLE process, CLIENT_ID *id, CONTEXT *ctx, INITIAL_TEB *teb,
                                     BOOLEAN suspended )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateThread );
}

NTSTATUS SYSCALL_API NtCreateThreadEx( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                       HANDLE process, PRTL_THREAD_START_ROUTINE start, void *param,
                                       ULONG flags, ULONG_PTR zero_bits, SIZE_T stack_commit,
                                       SIZE_T stack_reserve, PS_ATTRIBUTE_LIST *attr_list )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateThreadEx );
}

NTSTATUS SYSCALL_API NtCreateTimer( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                    TIMER_TYPE type )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateTimer );
}

NTSTATUS SYSCALL_API NtCreateToken( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                    TOKEN_TYPE type, LUID *token_id, LARGE_INTEGER *expire,
                                    TOKEN_USER *user, TOKEN_GROUPS *groups, TOKEN_PRIVILEGES *privs,
                                    TOKEN_OWNER *owner, TOKEN_PRIMARY_GROUP *group,
                                    TOKEN_DEFAULT_DACL *dacl, TOKEN_SOURCE *source )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateToken );
}

NTSTATUS SYSCALL_API NtCreateTransaction( HANDLE *handle, ACCESS_MASK mask, OBJECT_ATTRIBUTES *obj_attr,
                                          GUID *guid, HANDLE tm, ULONG options, ULONG isol_level,
                                          ULONG isol_flags, PLARGE_INTEGER timeout,
                                          UNICODE_STRING *description )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateTransaction );
}

NTSTATUS SYSCALL_API NtCreateUserProcess( HANDLE *process_handle_ptr, HANDLE *thread_handle_ptr,
                                          ACCESS_MASK process_access, ACCESS_MASK thread_access,
                                          OBJECT_ATTRIBUTES *process_attr, OBJECT_ATTRIBUTES *thread_attr,
                                          ULONG process_flags, ULONG thread_flags,
                                          RTL_USER_PROCESS_PARAMETERS *params, PS_CREATE_INFO *info,
                                          PS_ATTRIBUTE_LIST *ps_attr )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateUserProcess );
}

NTSTATUS SYSCALL_API NtDebugActiveProcess( HANDLE process, HANDLE debug )
{
    __ASM_SYSCALL_FUNC( __id_NtDebugActiveProcess );
}

NTSTATUS SYSCALL_API NtDebugContinue( HANDLE handle, CLIENT_ID *client, NTSTATUS status )
{
    __ASM_SYSCALL_FUNC( __id_NtDebugContinue );
}

NTSTATUS SYSCALL_API NtDelayExecution( BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtDelayExecution );
}

NTSTATUS SYSCALL_API NtDeleteAtom( RTL_ATOM atom )
{
    __ASM_SYSCALL_FUNC( __id_NtDeleteAtom );
}

NTSTATUS SYSCALL_API NtDeleteFile( OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtDeleteFile );
}

NTSTATUS SYSCALL_API NtDeleteKey( HANDLE key )
{
    __ASM_SYSCALL_FUNC( __id_NtDeleteKey );
}

NTSTATUS SYSCALL_API NtDeleteValueKey( HANDLE key, const UNICODE_STRING *name )
{
    __ASM_SYSCALL_FUNC( __id_NtDeleteValueKey );
}

NTSTATUS SYSCALL_API NtDeviceIoControlFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc,
                                            void *apc_context, IO_STATUS_BLOCK *io, ULONG code,
                                            void *in_buffer, ULONG in_size,
                                            void *out_buffer, ULONG out_size )
{
    __ASM_SYSCALL_FUNC( __id_NtDeviceIoControlFile );
}

NTSTATUS SYSCALL_API NtDisplayString( UNICODE_STRING *string )
{
    __ASM_SYSCALL_FUNC( __id_NtDisplayString );
}

NTSTATUS SYSCALL_API NtDuplicateObject( HANDLE source_process, HANDLE source, HANDLE dest_process,
                                        HANDLE *dest, ACCESS_MASK access, ULONG attributes, ULONG options )
{
    __ASM_SYSCALL_FUNC( __id_NtDuplicateObject );
}

NTSTATUS SYSCALL_API NtDuplicateToken( HANDLE token, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                       BOOLEAN effective_only, TOKEN_TYPE type, HANDLE *handle )
{
    __ASM_SYSCALL_FUNC( __id_NtDuplicateToken );
}

NTSTATUS SYSCALL_API NtEnumerateKey( HANDLE handle, ULONG index, KEY_INFORMATION_CLASS info_class,
                                     void *info, DWORD length, DWORD *result_len )
{
    __ASM_SYSCALL_FUNC( __id_NtEnumerateKey );
}

NTSTATUS SYSCALL_API NtEnumerateValueKey( HANDLE handle, ULONG index, KEY_VALUE_INFORMATION_CLASS info_class,
                                          void *info, DWORD length, DWORD *result_len )
{
    __ASM_SYSCALL_FUNC( __id_NtEnumerateValueKey );
}

NTSTATUS SYSCALL_API NtFilterToken( HANDLE token, ULONG flags, TOKEN_GROUPS *disable_sids,
                                    TOKEN_PRIVILEGES *privileges, TOKEN_GROUPS *restrict_sids,
                                    HANDLE *new_token )
{
    __ASM_SYSCALL_FUNC( __id_NtFilterToken );
}

NTSTATUS SYSCALL_API NtFindAtom( const WCHAR *name, ULONG length, RTL_ATOM *atom )
{
    __ASM_SYSCALL_FUNC( __id_NtFindAtom );
}

NTSTATUS SYSCALL_API NtFlushBuffersFile( HANDLE handle, IO_STATUS_BLOCK *io )
{
    __ASM_SYSCALL_FUNC( __id_NtFlushBuffersFile );
}

static NTSTATUS SYSCALL_API syscall_NtFlushInstructionCache( HANDLE handle, const void *addr, SIZE_T size )
{
    __ASM_SYSCALL_FUNC( __id_NtFlushInstructionCache );
}

NTSTATUS WINAPI NtFlushInstructionCache( HANDLE handle, const void *addr, SIZE_T size )
{
    if (RtlIsCurrentProcess( handle ) &&
        syscall_callback_begin( arm64ec_callbacks.pBTCpu64FlushInstructionCache ))
    {
        arm64ec_callbacks.pBTCpu64FlushInstructionCache( addr, size );
        syscall_callback_end();
    }

    return syscall_NtFlushInstructionCache( handle, addr, size );
}
NTSTATUS SYSCALL_API NtFlushKey( HANDLE key )
{
    __ASM_SYSCALL_FUNC( __id_NtFlushKey );
}

NTSTATUS SYSCALL_API NtFlushProcessWriteBuffers(void)
{
    __ASM_SYSCALL_FUNC( __id_NtFlushProcessWriteBuffers );
}

NTSTATUS SYSCALL_API NtFlushVirtualMemory( HANDLE process, LPCVOID *addr_ptr,
                                           SIZE_T *size_ptr, ULONG unknown )
{
    __ASM_SYSCALL_FUNC( __id_NtFlushVirtualMemory );
}

static NTSTATUS SYSCALL_API syscall_NtFreeVirtualMemory( HANDLE process, PVOID *addr_ptr,
                                                         SIZE_T *size_ptr, ULONG type )
{
    __ASM_SYSCALL_FUNC( __id_NtFreeVirtualMemory );
}

NTSTATUS WINAPI NtFreeVirtualMemory( HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr, ULONG type )
{
    if (RtlIsCurrentProcess( process ) &&
        syscall_callback_begin( arm64ec_callbacks.pNotifyMemoryFree )) {
        arm64ec_callbacks.pNotifyMemoryFree( *addr_ptr, *size_ptr, type );
        syscall_callback_end();
    }

    return syscall_NtFreeVirtualMemory( process, addr_ptr, size_ptr, type );
}

NTSTATUS SYSCALL_API NtFsControlFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_context,
                                      IO_STATUS_BLOCK *io, ULONG code, void *in_buffer, ULONG in_size,
                                      void *out_buffer, ULONG out_size )
{
    __ASM_SYSCALL_FUNC( __id_NtFsControlFile );
}

static NTSTATUS SYSCALL_API syscall_NtGetContextThread( HANDLE handle, ARM64_NT_CONTEXT *context )
{
    __ASM_SYSCALL_FUNC( __id_NtGetContextThread );
}

NTSTATUS WINAPI NtGetContextThread( HANDLE handle, CONTEXT *context )
{
    ARM64_NT_CONTEXT arm_ctx = { .ContextFlags = ctx_flags_x64_to_arm( context->ContextFlags ) };
    NTSTATUS status = syscall_NtGetContextThread( handle, &arm_ctx );

    if (!status) context_arm_to_x64( context, &arm_ctx );
    return status;
}

ULONG SYSCALL_API NtGetCurrentProcessorNumber(void)
{
    __ASM_SYSCALL_FUNC( __id_NtGetCurrentProcessorNumber );
}

NTSTATUS SYSCALL_API NtGetNextThread( HANDLE process, HANDLE thread, ACCESS_MASK access, ULONG attributes,
                                      ULONG flags, HANDLE *handle )
{
    __ASM_SYSCALL_FUNC( __id_NtGetNextThread );
}

NTSTATUS SYSCALL_API NtGetNlsSectionPtr( ULONG type, ULONG id, void *unknown, void **ptr, SIZE_T *size )
{
    __ASM_SYSCALL_FUNC( __id_NtGetNlsSectionPtr );
}

NTSTATUS SYSCALL_API NtGetWriteWatch( HANDLE process, ULONG flags, PVOID base, SIZE_T size,
                                      PVOID *addresses, ULONG_PTR *count, ULONG *granularity )
{
    __ASM_SYSCALL_FUNC( __id_NtGetWriteWatch );
}

NTSTATUS SYSCALL_API NtImpersonateAnonymousToken( HANDLE thread )
{
    __ASM_SYSCALL_FUNC( __id_NtImpersonateAnonymousToken );
}

NTSTATUS SYSCALL_API NtInitializeNlsFiles( void **ptr, LCID *lcid, LARGE_INTEGER *size )
{
    __ASM_SYSCALL_FUNC( __id_NtInitializeNlsFiles );
}

NTSTATUS SYSCALL_API NtInitiatePowerAction( POWER_ACTION action, SYSTEM_POWER_STATE state,
                                            ULONG flags, BOOLEAN async )
{
    __ASM_SYSCALL_FUNC( __id_NtInitiatePowerAction );
}

NTSTATUS SYSCALL_API NtIsProcessInJob( HANDLE process, HANDLE job )
{
    __ASM_SYSCALL_FUNC( __id_NtIsProcessInJob );
}

NTSTATUS SYSCALL_API NtListenPort( HANDLE handle, LPC_MESSAGE *msg )
{
    __ASM_SYSCALL_FUNC( __id_NtListenPort );
}

NTSTATUS SYSCALL_API NtLoadDriver( const UNICODE_STRING *name )
{
    __ASM_SYSCALL_FUNC( __id_NtLoadDriver );
}

NTSTATUS SYSCALL_API NtLoadKey( const OBJECT_ATTRIBUTES *attr, OBJECT_ATTRIBUTES *file )
{
    __ASM_SYSCALL_FUNC( __id_NtLoadKey );
}

NTSTATUS SYSCALL_API NtLoadKey2( const OBJECT_ATTRIBUTES *attr, OBJECT_ATTRIBUTES *file, ULONG flags )
{
    __ASM_SYSCALL_FUNC( __id_NtLoadKey2 );
}

NTSTATUS SYSCALL_API NtLoadKeyEx( const OBJECT_ATTRIBUTES *attr, OBJECT_ATTRIBUTES *file, ULONG flags,
                                  HANDLE trustkey, HANDLE event, ACCESS_MASK access,
                                  HANDLE *roothandle, IO_STATUS_BLOCK *iostatus )
{
    __ASM_SYSCALL_FUNC( __id_NtLoadKeyEx );
}

NTSTATUS SYSCALL_API NtLockFile( HANDLE file, HANDLE event, PIO_APC_ROUTINE apc, void* apc_user,
                                 IO_STATUS_BLOCK *io_status, LARGE_INTEGER *offset,
                                 LARGE_INTEGER *count, ULONG *key, BOOLEAN dont_wait, BOOLEAN exclusive )
{
    __ASM_SYSCALL_FUNC( __id_NtLockFile );
}

NTSTATUS SYSCALL_API NtLockVirtualMemory( HANDLE process, PVOID *addr, SIZE_T *size, ULONG unknown )
{
    __ASM_SYSCALL_FUNC( __id_NtLockVirtualMemory );
}

NTSTATUS SYSCALL_API NtMakeTemporaryObject( HANDLE handle )
{
    __ASM_SYSCALL_FUNC( __id_NtMakeTemporaryObject );
}

static NTSTATUS SYSCALL_API syscall_NtMapViewOfSection( HANDLE handle, HANDLE process, PVOID *addr_ptr,
                                                        ULONG_PTR zero_bits, SIZE_T commit_size,
                                                        const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                                        SECTION_INHERIT inherit, ULONG alloc_type, ULONG protect )
{
    __ASM_SYSCALL_FUNC( __id_NtMapViewOfSection );
}

NTSTATUS WINAPI NtMapViewOfSection( HANDLE handle, HANDLE process, PVOID *addr_ptr,
                                    ULONG_PTR zero_bits, SIZE_T commit_size,
                                    const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                    SECTION_INHERIT inherit, ULONG alloc_type, ULONG protect )
{
    NTSTATUS status = syscall_NtMapViewOfSection( handle, process, addr_ptr, zero_bits, commit_size,
                                                  offset_ptr, size_ptr, inherit, alloc_type, protect );
    if (NT_SUCCESS( status ) && RtlIsCurrentProcess( process ) &&
        syscall_callback_begin( arm64ec_callbacks.pNotifyMapViewOfSection ))
    {
        arm64ec_callbacks.pNotifyMapViewOfSection( *addr_ptr );
        syscall_callback_end();
    }
    return status;
}

static NTSTATUS SYSCALL_API syscall_NtMapViewOfSectionEx( HANDLE handle, HANDLE process, PVOID *addr_ptr,
                                                          const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                                          ULONG alloc_type, ULONG protect,
                                                          MEM_EXTENDED_PARAMETER *parameters, ULONG count )
{
    __ASM_SYSCALL_FUNC( __id_NtMapViewOfSectionEx );
}

NTSTATUS WINAPI NtMapViewOfSectionEx( HANDLE handle, HANDLE process, PVOID *addr_ptr,
                                      const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                      ULONG alloc_type, ULONG protect,
                                      MEM_EXTENDED_PARAMETER *parameters, ULONG count )
{
    NTSTATUS status = syscall_NtMapViewOfSectionEx( handle, process, addr_ptr, offset_ptr, size_ptr, alloc_type,
                                                    protect, parameters, count );
    if (NT_SUCCESS( status ) && RtlIsCurrentProcess( process ) &&
        syscall_callback_begin( arm64ec_callbacks.pNotifyMapViewOfSection ))
    {
        arm64ec_callbacks.pNotifyMapViewOfSection( *addr_ptr );
        syscall_callback_end();
    }
    return status;
}

NTSTATUS SYSCALL_API NtNotifyChangeDirectoryFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc,
                                                  void *apc_context, IO_STATUS_BLOCK *iosb, void *buffer,
                                                  ULONG buffer_size, ULONG filter, BOOLEAN subtree )
{
    __ASM_SYSCALL_FUNC( __id_NtNotifyChangeDirectoryFile );
}

NTSTATUS SYSCALL_API NtNotifyChangeKey( HANDLE key, HANDLE event, PIO_APC_ROUTINE apc, void *apc_context,
                                        IO_STATUS_BLOCK *io, ULONG filter, BOOLEAN subtree,
                                        void *buffer, ULONG length, BOOLEAN async )
{
    __ASM_SYSCALL_FUNC( __id_NtNotifyChangeKey );
}

NTSTATUS SYSCALL_API NtNotifyChangeMultipleKeys( HANDLE key, ULONG count, OBJECT_ATTRIBUTES *attr,
                                                 HANDLE event, PIO_APC_ROUTINE apc, void *apc_context,
                                                 IO_STATUS_BLOCK *io, ULONG filter, BOOLEAN subtree,
                                                 void *buffer, ULONG length, BOOLEAN async )
{
    __ASM_SYSCALL_FUNC( __id_NtNotifyChangeMultipleKeys );
}

NTSTATUS SYSCALL_API NtOpenDirectoryObject( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenDirectoryObject );
}

NTSTATUS SYSCALL_API NtOpenEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenEvent );
}

NTSTATUS SYSCALL_API NtOpenFile( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                 IO_STATUS_BLOCK *io, ULONG sharing, ULONG options )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenFile );
}

NTSTATUS SYSCALL_API NtOpenIoCompletion( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenIoCompletion );
}

NTSTATUS SYSCALL_API NtOpenJobObject( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenJobObject );
}

NTSTATUS SYSCALL_API NtOpenKey( HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenKey );
}

NTSTATUS SYSCALL_API NtOpenKeyEx( HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, ULONG options )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenKeyEx );
}

NTSTATUS SYSCALL_API NtOpenKeyTransacted( HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                          HANDLE transaction )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenKeyTransacted );
}

NTSTATUS SYSCALL_API NtOpenKeyTransactedEx( HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                            ULONG options, HANDLE transaction )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenKeyTransactedEx );
}

NTSTATUS SYSCALL_API NtOpenKeyedEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenKeyedEvent );
}

NTSTATUS SYSCALL_API NtOpenMutant( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenMutant );
}

NTSTATUS SYSCALL_API NtOpenProcess( HANDLE *handle, ACCESS_MASK access,
                                    const OBJECT_ATTRIBUTES *attr, const CLIENT_ID *id )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenProcess );
}

NTSTATUS SYSCALL_API NtOpenProcessToken( HANDLE process, DWORD access, HANDLE *handle )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenProcessToken );
}

NTSTATUS SYSCALL_API NtOpenProcessTokenEx( HANDLE process, DWORD access, DWORD attributes, HANDLE *handle )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenProcessTokenEx );
}

NTSTATUS SYSCALL_API NtOpenSection( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenSection );
}

NTSTATUS SYSCALL_API NtOpenSemaphore( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenSemaphore );
}

NTSTATUS SYSCALL_API NtOpenSymbolicLinkObject( HANDLE *handle, ACCESS_MASK access,
                                               const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenSymbolicLinkObject );
}

NTSTATUS SYSCALL_API NtOpenThread( HANDLE *handle, ACCESS_MASK access,
                                   const OBJECT_ATTRIBUTES *attr, const CLIENT_ID *id )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenThread );
}

NTSTATUS SYSCALL_API NtOpenThreadToken( HANDLE thread, DWORD access, BOOLEAN self, HANDLE *handle )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenThreadToken );
}

NTSTATUS SYSCALL_API NtOpenThreadTokenEx( HANDLE thread, DWORD access, BOOLEAN self, DWORD attributes,
                                          HANDLE *handle )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenThreadTokenEx );
}

NTSTATUS SYSCALL_API NtOpenTimer( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenTimer );
}

NTSTATUS SYSCALL_API NtPowerInformation( POWER_INFORMATION_LEVEL level, void *input, ULONG in_size,
                                         void *output, ULONG out_size )
{
    __ASM_SYSCALL_FUNC( __id_NtPowerInformation );
}

NTSTATUS SYSCALL_API NtPrivilegeCheck( HANDLE token, PRIVILEGE_SET *privs, BOOLEAN *res )
{
    __ASM_SYSCALL_FUNC( __id_NtPrivilegeCheck );
}

static NTSTATUS SYSCALL_API syscall_NtProtectVirtualMemory( HANDLE process, PVOID *addr_ptr,
                                                            SIZE_T *size_ptr, ULONG new_prot,
                                                            ULONG *old_prot )
{
    __ASM_SYSCALL_FUNC( __id_NtProtectVirtualMemory );
}

NTSTATUS WINAPI NtProtectVirtualMemory( HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr,
                                        ULONG new_prot, ULONG *old_prot )
{
    if (RtlIsCurrentProcess( process ) &&
        syscall_callback_begin( arm64ec_callbacks.pNotifyMemoryProtect )) {
        arm64ec_callbacks.pNotifyMemoryProtect( *addr_ptr, *size_ptr, new_prot );
        syscall_callback_end();
    }

    return syscall_NtProtectVirtualMemory( process, addr_ptr, size_ptr, new_prot, old_prot );
}

NTSTATUS SYSCALL_API NtPulseEvent( HANDLE handle, LONG *prev_state )
{
    __ASM_SYSCALL_FUNC( __id_NtPulseEvent );
}

NTSTATUS SYSCALL_API NtQueryAttributesFile( const OBJECT_ATTRIBUTES *attr, FILE_BASIC_INFORMATION *info )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryAttributesFile );
}

NTSTATUS SYSCALL_API NtQueryDefaultLocale( BOOLEAN user, LCID *lcid )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryDefaultLocale );
}

NTSTATUS SYSCALL_API NtQueryDefaultUILanguage( LANGID *lang )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryDefaultUILanguage );
}

NTSTATUS SYSCALL_API NtQueryDirectoryFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc_routine,
                                           void *apc_context, IO_STATUS_BLOCK *io, void *buffer,
                                           ULONG length, FILE_INFORMATION_CLASS info_class,
                                           BOOLEAN single_entry, UNICODE_STRING *mask,
                                           BOOLEAN restart_scan )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryDirectoryFile );
}

NTSTATUS SYSCALL_API NtQueryDirectoryObject( HANDLE handle, DIRECTORY_BASIC_INFORMATION *buffer,
                                             ULONG size, BOOLEAN single_entry, BOOLEAN restart,
                                             ULONG *context, ULONG *ret_size )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryDirectoryObject );
}

NTSTATUS SYSCALL_API NtQueryEaFile( HANDLE handle, IO_STATUS_BLOCK *io, void *buffer, ULONG length,
                                    BOOLEAN single_entry, void *list, ULONG list_len,
                                    ULONG *index, BOOLEAN restart )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryEaFile );
}

NTSTATUS SYSCALL_API NtQueryEvent( HANDLE handle, EVENT_INFORMATION_CLASS class,
                                   void *info, ULONG len, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryEvent );
}

NTSTATUS SYSCALL_API NtQueryFullAttributesFile( const OBJECT_ATTRIBUTES *attr,
                                                FILE_NETWORK_OPEN_INFORMATION *info )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryFullAttributesFile );
}

NTSTATUS SYSCALL_API NtQueryInformationAtom( RTL_ATOM atom, ATOM_INFORMATION_CLASS class,
                                             void *ptr, ULONG size, ULONG *retsize )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryInformationAtom );
}

NTSTATUS SYSCALL_API NtQueryInformationFile( HANDLE handle, IO_STATUS_BLOCK *io,
                                             void *ptr, ULONG len, FILE_INFORMATION_CLASS class )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryInformationFile );
}

NTSTATUS SYSCALL_API NtQueryInformationJobObject( HANDLE handle, JOBOBJECTINFOCLASS class, void *info,
                                                  ULONG len, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryInformationJobObject );
}

NTSTATUS SYSCALL_API NtQueryInformationProcess( HANDLE handle, PROCESSINFOCLASS class, void *info,
                                                ULONG size, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryInformationProcess );
}

NTSTATUS SYSCALL_API NtQueryInformationThread( HANDLE handle, THREADINFOCLASS class,
                                               void *data, ULONG length, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryInformationThread );
}

NTSTATUS SYSCALL_API NtQueryInformationToken( HANDLE token, TOKEN_INFORMATION_CLASS class,
                                              void *info, ULONG length, ULONG *retlen )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryInformationToken );
}

NTSTATUS SYSCALL_API NtQueryInstallUILanguage( LANGID *lang )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryInstallUILanguage );
}

NTSTATUS SYSCALL_API NtQueryIoCompletion( HANDLE handle, IO_COMPLETION_INFORMATION_CLASS class,
                                          void *buffer, ULONG len, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryIoCompletion );
}

NTSTATUS SYSCALL_API NtQueryKey( HANDLE handle, KEY_INFORMATION_CLASS info_class,
                                 void *info, DWORD length, DWORD *result_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryKey );
}

NTSTATUS SYSCALL_API NtQueryLicenseValue( const UNICODE_STRING *name, ULONG *type,
                                          void *data, ULONG length, ULONG *retlen )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryLicenseValue );
}

NTSTATUS SYSCALL_API NtQueryMultipleValueKey( HANDLE key, KEY_MULTIPLE_VALUE_INFORMATION *info,
                                              ULONG count, void *buffer, ULONG length, ULONG *retlen )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryMultipleValueKey );
}

NTSTATUS SYSCALL_API NtQueryMutant( HANDLE handle, MUTANT_INFORMATION_CLASS class,
                                    void *info, ULONG len, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryMutant );
}

NTSTATUS SYSCALL_API NtQueryObject( HANDLE handle, OBJECT_INFORMATION_CLASS info_class,
                                    void *ptr, ULONG len, ULONG *used_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryObject );
}

NTSTATUS SYSCALL_API NtQueryPerformanceCounter( LARGE_INTEGER *counter, LARGE_INTEGER *frequency )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryPerformanceCounter );
}

NTSTATUS SYSCALL_API NtQuerySection( HANDLE handle, SECTION_INFORMATION_CLASS class, void *ptr,
                                     SIZE_T size, SIZE_T *ret_size )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySection );
}

NTSTATUS SYSCALL_API NtQuerySecurityObject( HANDLE handle, SECURITY_INFORMATION info,
                                            PSECURITY_DESCRIPTOR descr, ULONG length, ULONG *retlen )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySecurityObject );
}

NTSTATUS SYSCALL_API NtQuerySemaphore( HANDLE handle, SEMAPHORE_INFORMATION_CLASS class,
                                       void *info, ULONG len, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySemaphore );
}

NTSTATUS SYSCALL_API NtQuerySymbolicLinkObject( HANDLE handle, UNICODE_STRING *target, ULONG *length )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySymbolicLinkObject );
}

NTSTATUS SYSCALL_API NtQuerySystemEnvironmentValue( UNICODE_STRING *name, WCHAR *buffer, ULONG length,
                                                    ULONG *retlen )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySystemEnvironmentValue );
}

NTSTATUS SYSCALL_API NtQuerySystemEnvironmentValueEx( UNICODE_STRING *name, GUID *vendor, void *buffer,
                                                      ULONG *retlen, ULONG *attrib )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySystemEnvironmentValueEx );
}

static NTSTATUS SYSCALL_API syscall_NtQuerySystemInformation( SYSTEM_INFORMATION_CLASS class,
                                                              void *info, ULONG size, ULONG *ret_size )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySystemInformation );
}

NTSTATUS WINAPI NtQuerySystemInformation( SYSTEM_INFORMATION_CLASS class,
                                          void *info, ULONG size, ULONG *ret_size )
{
    NTSTATUS status = syscall_NtQuerySystemInformation( class, info, size, ret_size );
    // TODO: check windows behaviour when called from non x86 code
    if (!status && class == SystemCpuInformation &&
        syscall_callback_begin( arm64ec_callbacks.pUpdateProcessorInformation ))
    {
        arm64ec_callbacks.pUpdateProcessorInformation( info );
        syscall_callback_end();
    }

    return status;
}

NTSTATUS SYSCALL_API NtQuerySystemInformationEx( SYSTEM_INFORMATION_CLASS class, void *query,
                                                 ULONG query_len, void *info, ULONG size, ULONG *ret_size )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySystemInformationEx );
}

NTSTATUS SYSCALL_API NtQuerySystemTime( LARGE_INTEGER *time )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySystemTime );
}

NTSTATUS SYSCALL_API NtQueryTimer( HANDLE handle, TIMER_INFORMATION_CLASS class,
                                   void *info, ULONG len, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryTimer );
}

NTSTATUS SYSCALL_API NtQueryTimerResolution( ULONG *min_res, ULONG *max_res, ULONG *current_res )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryTimerResolution );
}

NTSTATUS SYSCALL_API NtQueryValueKey( HANDLE handle, const UNICODE_STRING *name,
                                      KEY_VALUE_INFORMATION_CLASS info_class,
                                      void *info, DWORD length, DWORD *result_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryValueKey );
}

NTSTATUS SYSCALL_API NtQueryVirtualMemory( HANDLE process, LPCVOID addr, MEMORY_INFORMATION_CLASS info_class,
                                           PVOID buffer, SIZE_T len, SIZE_T *res_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryVirtualMemory );
}

NTSTATUS SYSCALL_API NtQueryVolumeInformationFile( HANDLE handle, IO_STATUS_BLOCK *io, void *buffer,
                                                   ULONG length, FS_INFORMATION_CLASS info_class )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryVolumeInformationFile );
}

NTSTATUS SYSCALL_API NtQueueApcThread( HANDLE handle, PNTAPCFUNC func, ULONG_PTR arg1,
                                       ULONG_PTR arg2, ULONG_PTR arg3 )
{
    __ASM_SYSCALL_FUNC( __id_NtQueueApcThread );
}

NTSTATUS SYSCALL_API syscall_NtRaiseException( EXCEPTION_RECORD *rec, ARM64_NT_CONTEXT *context, BOOL first_chance )
{
    __ASM_SYSCALL_FUNC( __id_NtRaiseException );
}

NTSTATUS WINAPI NtRaiseException( EXCEPTION_RECORD *rec, CONTEXT *context, BOOL first_chance )
{
    ARM64_NT_CONTEXT arm_ctx;

    context_x64_to_arm( &arm_ctx, context );
    return syscall_NtRaiseException( rec, &arm_ctx, first_chance );
}

NTSTATUS SYSCALL_API NtRaiseHardError( NTSTATUS status, ULONG count, UNICODE_STRING *params_mask,
                                       void **params, HARDERROR_RESPONSE_OPTION option,
                                       HARDERROR_RESPONSE *response )
{
    __ASM_SYSCALL_FUNC( __id_NtRaiseHardError );
}

NTSTATUS SYSCALL_API NtReadFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                 IO_STATUS_BLOCK *io, void *buffer, ULONG length,
                                 LARGE_INTEGER *offset, ULONG *key )
{
    __ASM_SYSCALL_FUNC( __id_NtReadFile );
}

NTSTATUS SYSCALL_API NtReadFileScatter( HANDLE file, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                        IO_STATUS_BLOCK *io, FILE_SEGMENT_ELEMENT *segments,
                                        ULONG length, LARGE_INTEGER *offset, ULONG *key )
{
    __ASM_SYSCALL_FUNC( __id_NtReadFileScatter );
}

NTSTATUS SYSCALL_API NtReadVirtualMemory( HANDLE process, const void *addr, void *buffer,
                                          SIZE_T size, SIZE_T *bytes_read )
{
    __ASM_SYSCALL_FUNC( __id_NtReadVirtualMemory );
}

NTSTATUS SYSCALL_API NtRegisterThreadTerminatePort( HANDLE handle )
{
    __ASM_SYSCALL_FUNC( __id_NtRegisterThreadTerminatePort );
}

NTSTATUS SYSCALL_API NtReleaseKeyedEvent( HANDLE handle, const void *key,
                                          BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtReleaseKeyedEvent );
}

NTSTATUS SYSCALL_API NtReleaseMutant( HANDLE handle, LONG *prev_count )
{
    __ASM_SYSCALL_FUNC( __id_NtReleaseMutant );
}

NTSTATUS SYSCALL_API NtReleaseSemaphore( HANDLE handle, ULONG count, ULONG *previous )
{
    __ASM_SYSCALL_FUNC( __id_NtReleaseSemaphore );
}

NTSTATUS SYSCALL_API NtRemoveIoCompletion( HANDLE handle, ULONG_PTR *key, ULONG_PTR *value,
                                           IO_STATUS_BLOCK *io, LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtRemoveIoCompletion );
}

NTSTATUS SYSCALL_API NtRemoveIoCompletionEx( HANDLE handle, FILE_IO_COMPLETION_INFORMATION *info,
                                             ULONG count, ULONG *written, LARGE_INTEGER *timeout,
                                             BOOLEAN alertable )
{
    __ASM_SYSCALL_FUNC( __id_NtRemoveIoCompletionEx );
}

NTSTATUS SYSCALL_API NtRemoveProcessDebug( HANDLE process, HANDLE debug )
{
    __ASM_SYSCALL_FUNC( __id_NtRemoveProcessDebug );
}

NTSTATUS SYSCALL_API NtRenameKey( HANDLE key, UNICODE_STRING *name )
{
    __ASM_SYSCALL_FUNC( __id_NtRenameKey );
}

NTSTATUS SYSCALL_API NtReplaceKey( OBJECT_ATTRIBUTES *attr, HANDLE key, OBJECT_ATTRIBUTES *replace )
{
    __ASM_SYSCALL_FUNC( __id_NtReplaceKey );
}

NTSTATUS SYSCALL_API NtReplyWaitReceivePort( HANDLE handle, ULONG *id, LPC_MESSAGE *reply, LPC_MESSAGE *msg )
{
    __ASM_SYSCALL_FUNC( __id_NtReplyWaitReceivePort );
}

NTSTATUS SYSCALL_API NtRequestWaitReplyPort( HANDLE handle, LPC_MESSAGE *msg_in, LPC_MESSAGE *msg_out )
{
    __ASM_SYSCALL_FUNC( __id_NtRequestWaitReplyPort );
}

NTSTATUS SYSCALL_API NtResetEvent( HANDLE handle, LONG *prev_state )
{
    __ASM_SYSCALL_FUNC( __id_NtResetEvent );
}

NTSTATUS SYSCALL_API NtResetWriteWatch( HANDLE process, PVOID base, SIZE_T size )
{
    __ASM_SYSCALL_FUNC( __id_NtResetWriteWatch );
}

NTSTATUS SYSCALL_API NtRestoreKey( HANDLE key, HANDLE file, ULONG flags )
{
    __ASM_SYSCALL_FUNC( __id_NtRestoreKey );
}

NTSTATUS SYSCALL_API NtResumeProcess( HANDLE handle )
{
    __ASM_SYSCALL_FUNC( __id_NtResumeProcess );
}

NTSTATUS SYSCALL_API NtResumeThread( HANDLE handle, ULONG *count )
{
    __ASM_SYSCALL_FUNC( __id_NtResumeThread );
}

NTSTATUS SYSCALL_API NtRollbackTransaction( HANDLE transaction, BOOLEAN wait )
{
    __ASM_SYSCALL_FUNC( __id_NtRollbackTransaction );
}

NTSTATUS SYSCALL_API NtSaveKey( HANDLE key, HANDLE file )
{
    __ASM_SYSCALL_FUNC( __id_NtSaveKey );
}

NTSTATUS SYSCALL_API NtSecureConnectPort( HANDLE *handle, UNICODE_STRING *name,
                                          SECURITY_QUALITY_OF_SERVICE *qos, LPC_SECTION_WRITE *write,
                                          PSID sid, LPC_SECTION_READ *read, ULONG *max_len,
                                          void *info, ULONG *info_len )
{
    __ASM_SYSCALL_FUNC( __id_NtSecureConnectPort );
}

static NTSTATUS SYSCALL_API syscall_NtSetContextThread( HANDLE handle, const ARM64_NT_CONTEXT *context )
{
    __ASM_SYSCALL_FUNC( __id_NtSetContextThread );
}

NTSTATUS WINAPI NtSetContextThread( HANDLE handle, const CONTEXT *context )
{
    ARM64_NT_CONTEXT arm_ctx;

    context_x64_to_arm( &arm_ctx, context );
    return syscall_NtSetContextThread( handle, &arm_ctx );
}

NTSTATUS SYSCALL_API NtSetDebugFilterState( ULONG component_id, ULONG level, BOOLEAN state )
{
    __ASM_SYSCALL_FUNC( __id_NtSetDebugFilterState );
}

NTSTATUS SYSCALL_API NtSetDefaultLocale( BOOLEAN user, LCID lcid )
{
    __ASM_SYSCALL_FUNC( __id_NtSetDefaultLocale );
}

NTSTATUS SYSCALL_API NtSetDefaultUILanguage( LANGID lang )
{
    __ASM_SYSCALL_FUNC( __id_NtSetDefaultUILanguage );
}

NTSTATUS SYSCALL_API NtSetEaFile( HANDLE handle, IO_STATUS_BLOCK *io, void *buffer, ULONG length )
{
    __ASM_SYSCALL_FUNC( __id_NtSetEaFile );
}

NTSTATUS SYSCALL_API NtSetEvent( HANDLE handle, LONG *prev_state )
{
    __ASM_SYSCALL_FUNC( __id_NtSetEvent );
}

NTSTATUS SYSCALL_API NtSetInformationDebugObject( HANDLE handle, DEBUGOBJECTINFOCLASS class,
                                                  void *info, ULONG len, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationDebugObject );
}

NTSTATUS SYSCALL_API NtSetInformationFile( HANDLE handle, IO_STATUS_BLOCK *io,
                                           void *ptr, ULONG len, FILE_INFORMATION_CLASS class )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationFile );
}

NTSTATUS SYSCALL_API NtSetInformationJobObject( HANDLE handle, JOBOBJECTINFOCLASS class,
                                                void *info, ULONG len )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationJobObject );
}

NTSTATUS SYSCALL_API NtSetInformationKey( HANDLE key, int class, void *info, ULONG length )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationKey );
}

NTSTATUS SYSCALL_API NtSetInformationObject( HANDLE handle, OBJECT_INFORMATION_CLASS info_class,
                                             void *ptr, ULONG len )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationObject );
}

NTSTATUS SYSCALL_API NtSetInformationProcess( HANDLE handle, PROCESSINFOCLASS class,
                                              void *info, ULONG size )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationProcess );
}

NTSTATUS SYSCALL_API NtSetInformationThread( HANDLE handle, THREADINFOCLASS class,
                                             const void *data, ULONG length )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationThread );
}

NTSTATUS SYSCALL_API NtSetInformationToken( HANDLE token, TOKEN_INFORMATION_CLASS class,
                                            void *info, ULONG length )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationToken );
}

NTSTATUS SYSCALL_API NtSetInformationVirtualMemory( HANDLE process,
                                                    VIRTUAL_MEMORY_INFORMATION_CLASS info_class,
                                                    ULONG_PTR count, PMEMORY_RANGE_ENTRY addresses,
                                                    PVOID ptr, ULONG size )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationVirtualMemory );
}

NTSTATUS SYSCALL_API NtSetIntervalProfile( ULONG interval, KPROFILE_SOURCE source )
{
    __ASM_SYSCALL_FUNC( __id_NtSetIntervalProfile );
}

NTSTATUS SYSCALL_API NtSetIoCompletion( HANDLE handle, ULONG_PTR key, ULONG_PTR value,
                                        NTSTATUS status, SIZE_T count )
{
    __ASM_SYSCALL_FUNC( __id_NtSetIoCompletion );
}

NTSTATUS SYSCALL_API NtSetLdtEntries( ULONG sel1, LDT_ENTRY entry1, ULONG sel2, LDT_ENTRY entry2 )
{
    __ASM_SYSCALL_FUNC( __id_NtSetLdtEntries );
}

NTSTATUS SYSCALL_API NtSetSecurityObject( HANDLE handle, SECURITY_INFORMATION info,
                                          PSECURITY_DESCRIPTOR descr )
{
    __ASM_SYSCALL_FUNC( __id_NtSetSecurityObject );
}

NTSTATUS SYSCALL_API NtSetSystemInformation( SYSTEM_INFORMATION_CLASS class, void *info, ULONG length )
{
    __ASM_SYSCALL_FUNC( __id_NtSetSystemInformation );
}

NTSTATUS SYSCALL_API NtSetSystemTime( const LARGE_INTEGER *new, LARGE_INTEGER *old )
{
    __ASM_SYSCALL_FUNC( __id_NtSetSystemTime );
}

NTSTATUS SYSCALL_API NtSetThreadExecutionState( EXECUTION_STATE new_state, EXECUTION_STATE *old_state )
{
    __ASM_SYSCALL_FUNC( __id_NtSetThreadExecutionState );
}

NTSTATUS SYSCALL_API NtSetTimer( HANDLE handle, const LARGE_INTEGER *when, PTIMER_APC_ROUTINE callback,
                                 void *arg, BOOLEAN resume, ULONG period, BOOLEAN *state )
{
    __ASM_SYSCALL_FUNC( __id_NtSetTimer );
}

NTSTATUS SYSCALL_API NtSetTimerResolution( ULONG res, BOOLEAN set, ULONG *current_res )
{
    __ASM_SYSCALL_FUNC( __id_NtSetTimerResolution );
}

NTSTATUS SYSCALL_API NtSetValueKey( HANDLE key, const UNICODE_STRING *name, ULONG index,
                                    ULONG type, const void *data, ULONG count )
{
    __ASM_SYSCALL_FUNC( __id_NtSetValueKey );
}

NTSTATUS SYSCALL_API NtSetVolumeInformationFile( HANDLE handle, IO_STATUS_BLOCK *io, void *info,
                                                 ULONG length, FS_INFORMATION_CLASS class )
{
    __ASM_SYSCALL_FUNC( __id_NtSetVolumeInformationFile );
}

NTSTATUS SYSCALL_API NtShutdownSystem( SHUTDOWN_ACTION action )
{
    __ASM_SYSCALL_FUNC( __id_NtShutdownSystem );
}

NTSTATUS SYSCALL_API NtSignalAndWaitForSingleObject( HANDLE signal, HANDLE wait,
                                                     BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtSignalAndWaitForSingleObject );
}

NTSTATUS SYSCALL_API NtSuspendProcess( HANDLE handle )
{
    __ASM_SYSCALL_FUNC( __id_NtSuspendProcess );
}

NTSTATUS SYSCALL_API NtSuspendThread( HANDLE handle, ULONG *count )
{
    __ASM_SYSCALL_FUNC( __id_NtSuspendThread );
}

NTSTATUS SYSCALL_API NtSystemDebugControl( SYSDBG_COMMAND command, void *in_buff, ULONG in_len,
                                           void *out_buff, ULONG out_len, ULONG *retlen )
{
    __ASM_SYSCALL_FUNC( __id_NtSystemDebugControl );
}

NTSTATUS SYSCALL_API NtTerminateJobObject( HANDLE handle, NTSTATUS status )
{
    __ASM_SYSCALL_FUNC( __id_NtTerminateJobObject );
}

NTSTATUS SYSCALL_API NtTerminateProcess( HANDLE handle, LONG exit_code )
{
    __ASM_SYSCALL_FUNC( __id_NtTerminateProcess );
}

static NTSTATUS SYSCALL_API syscall_NtTerminateThread( HANDLE handle, LONG exit_code )
{
    __ASM_SYSCALL_FUNC( __id_NtTerminateThread );
}

NTSTATUS WINAPI NtTerminateThread( HANDLE handle, LONG exit_code )
{
    if (syscall_callback_begin( arm64ec_callbacks.pThreadTerm) )
    {
        arm64ec_callbacks.pThreadTerm( handle );
	syscall_callback_end();
    }
    return syscall_NtTerminateThread( handle, exit_code );
}

NTSTATUS SYSCALL_API NtTestAlert(void)
{
    __ASM_SYSCALL_FUNC( __id_NtTestAlert );
}

NTSTATUS SYSCALL_API NtTraceControl( ULONG code, void *inbuf, ULONG inbuf_len,
                                     void *outbuf, ULONG outbuf_len, ULONG *size )
{
    __ASM_SYSCALL_FUNC( __id_NtTraceControl );
}

NTSTATUS SYSCALL_API NtUnloadDriver( const UNICODE_STRING *name )
{
    __ASM_SYSCALL_FUNC( __id_NtUnloadDriver );
}

NTSTATUS SYSCALL_API NtUnloadKey( OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtUnloadKey );
}

NTSTATUS SYSCALL_API NtUnlockFile( HANDLE handle, IO_STATUS_BLOCK *io_status, LARGE_INTEGER *offset,
                                   LARGE_INTEGER *count, ULONG *key )
{
    __ASM_SYSCALL_FUNC( __id_NtUnlockFile );
}

NTSTATUS SYSCALL_API NtUnlockVirtualMemory( HANDLE process, PVOID *addr, SIZE_T *size, ULONG unknown )
{
    __ASM_SYSCALL_FUNC( __id_NtUnlockVirtualMemory );
}

static NTSTATUS SYSCALL_API syscall_NtUnmapViewOfSection( HANDLE process, PVOID addr )
{
    __ASM_SYSCALL_FUNC( __id_NtUnmapViewOfSection );
}

NTSTATUS WINAPI NtUnmapViewOfSection( HANDLE process, PVOID addr )
{
    if (RtlIsCurrentProcess( process ) &&
        syscall_callback_begin( arm64ec_callbacks.pNotifyUnmapViewOfSection )) {
        arm64ec_callbacks.pNotifyUnmapViewOfSection( addr );
        syscall_callback_end();
    }

    return syscall_NtUnmapViewOfSection( process, addr );
}

static NTSTATUS SYSCALL_API syscall_NtUnmapViewOfSectionEx( HANDLE process, PVOID addr, ULONG flags )
{
    __ASM_SYSCALL_FUNC( __id_NtUnmapViewOfSectionEx );
}

NTSTATUS WINAPI NtUnmapViewOfSectionEx( HANDLE process, PVOID addr, ULONG flags )
{
    if (RtlIsCurrentProcess( process ) &&
        syscall_callback_begin( arm64ec_callbacks.pNotifyUnmapViewOfSection )) {
        arm64ec_callbacks.pNotifyUnmapViewOfSection( addr );
        syscall_callback_end();
    }

    return syscall_NtUnmapViewOfSectionEx( process, addr, flags );
}

NTSTATUS SYSCALL_API NtWaitForAlertByThreadId( const void *address, const LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtWaitForAlertByThreadId );
}

NTSTATUS SYSCALL_API NtWaitForDebugEvent( HANDLE handle, BOOLEAN alertable, LARGE_INTEGER *timeout,
                                          DBGUI_WAIT_STATE_CHANGE *state )
{
    __ASM_SYSCALL_FUNC( __id_NtWaitForDebugEvent );
}

NTSTATUS SYSCALL_API NtWaitForKeyedEvent( HANDLE handle, const void *key,
                                          BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtWaitForKeyedEvent );
}

NTSTATUS SYSCALL_API NtWaitForMultipleObjects( DWORD count, const HANDLE *handles, BOOLEAN wait_any,
                                               BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtWaitForMultipleObjects );
}

NTSTATUS SYSCALL_API NtWaitForSingleObject( HANDLE handle, BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtWaitForSingleObject );
}

NTSTATUS SYSCALL_API NtWriteFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                  IO_STATUS_BLOCK *io, const void *buffer, ULONG length,
                                  LARGE_INTEGER *offset, ULONG *key )
{
    __ASM_SYSCALL_FUNC( __id_NtWriteFile );
}

NTSTATUS SYSCALL_API NtWriteFileGather( HANDLE file, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                        IO_STATUS_BLOCK *io, FILE_SEGMENT_ELEMENT *segments,
                                        ULONG length, LARGE_INTEGER *offset, ULONG *key )
{
    __ASM_SYSCALL_FUNC( __id_NtWriteFileGather );
}

NTSTATUS SYSCALL_API NtWriteVirtualMemory( HANDLE process, void *addr, const void *buffer,
                                           SIZE_T size, SIZE_T *bytes_written )
{
    __ASM_SYSCALL_FUNC( __id_NtWriteVirtualMemory );
}

NTSTATUS SYSCALL_API NtYieldExecution(void)
{
    __ASM_SYSCALL_FUNC( __id_NtYieldExecution );
}

NTSTATUS SYSCALL_API wine_nt_to_unix_file_name( const OBJECT_ATTRIBUTES *attr, char *nameA, ULONG *size,
                                                UINT disposition )
{
    __ASM_SYSCALL_FUNC( __id_wine_nt_to_unix_file_name );
}

NTSTATUS SYSCALL_API wine_unix_to_nt_file_name( const char *name, WCHAR *buffer, ULONG *size )
{
    __ASM_SYSCALL_FUNC( __id_wine_unix_to_nt_file_name );
}

static void * const arm64ec_syscalls[] =
{
#define SYSCALL_ENTRY(id,name,args) name,
    ALL_SYSCALLS64
#undef SYSCALL_ENTRY
};


/***********************************************************************
 *           LdrpGetX64Information
 */
static NTSTATUS WINAPI LdrpGetX64Information( ULONG type, void *output, void *extra_info )
{
    switch (type)
    {
    case 0:
    {
        UINT64 fpcr, fpsr;

        __asm__ __volatile__( "mrs %0, fpcr; mrs %1, fpsr" : "=r" (fpcr), "=r" (fpsr) );
        *(UINT *)output = fpcsr_to_mxcsr( fpcr, fpsr );
        return STATUS_SUCCESS;
    }
    default:
        FIXME( "not implemented type %u\n", type );
        return STATUS_INVALID_PARAMETER;
    }
}

/***********************************************************************
 *           LdrpSetX64Information
 */
static NTSTATUS WINAPI LdrpSetX64Information( ULONG type, ULONG_PTR input, void *extra_info )
{
    switch (type)
    {
    case 0:
    {
        UINT64 fpcsr = mxcsr_to_fpcsr( input );
        __asm__ __volatile__( "msr fpcr, %0; msr fpsr, %1" :: "r" (fpcsr), "r" (fpcsr >> 32) );
        return STATUS_SUCCESS;
    }
    default:
        FIXME( "not implemented type %u\n", type );
        return STATUS_INVALID_PARAMETER;
    }
}


/*******************************************************************
 *                dispatch_emulation
 */
void WINAPI dispatch_emulation( ARM64_NT_CONTEXT *arm_ctx )
{
    context_arm_to_x64( (CONTEXT *)NtCurrentTeb()->ChpeV2CpuAreaInfo->ContextAmd64, arm_ctx );
    arm64ec_callbacks.pBeginSimulation();
}

/*******************************************************************
 *                KiUserEmulationDispatcher (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( "#KiUserEmulationDispatcher",
                   __ASM_SEH(".seh_context\n\t")
                   __ASM_SEH(".seh_endprologue\n\t")
                   "mov x0, sp\n\t"        /* context */
                   "bl " __ASM_NAME("dispatch_emulation") "\n\t"
                   "brk #1" )

NTSTATUS dispatch_exception_ec( EXCEPTION_RECORD *rec, ARM64_NT_CONTEXT *arm_context )
{
    CONTEXT context;
    EXCEPTION_POINTERS pointers = { rec, &context };

    context_arm_to_x64( &context, arm_context );
    arm64ec_callbacks.pResetToConsistentState( &pointers );
    context_x64_to_arm( arm_context, &context );

    return dispatch_exception( rec, &context );
}

/*******************************************************************
 *                KiUserExceptionDispatcher (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( "#KiUserExceptionDispatcher",
                   "nop\n\t"
                   __ASM_SEH(".seh_context\n\t")
                   __ASM_SEH(".seh_endprologue\n\t")
                   "add x0, sp, #0x390\n\t" /* rec (context + 1) */
                   "mov x1, sp\n\t"             /* context */
                   "bl " __ASM_NAME("dispatch_exception_ec") "\n\t"
                   "brk #1" )

/*******************************************************************
 *                KiUserApcDispatcher (NTDLL.@)
 */
void WINAPI dispatch_apc( void (CALLBACK *func)(ULONG_PTR,ULONG_PTR,ULONG_PTR,CONTEXT*),
                          ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3,
                          BOOLEAN alertable, ARM64_NT_CONTEXT *arm_ctx )
{
    CONTEXT context;

    context_arm_to_x64( &context, arm_ctx );
    func( arg1, arg2, arg3, &context );
    NtContinue( &context, alertable );
}
__ASM_GLOBAL_FUNC( "#KiUserApcDispatcher",
                   __ASM_SEH(".seh_context\n\t")
                   "nop\n\t"
                   __ASM_SEH(".seh_stackalloc 0x30\n\t")
                   __ASM_SEH(".seh_endprologue\n\t")
                   "ldp x0, x1, [sp]\n\t"         /* func, arg1 */
                   "ldp x2, x3, [sp, #0x10]\n\t"  /* arg2, arg3 */
                   "ldr w4, [sp, #0x20]\n\t"      /* alertable */
                   "add x5, sp, #0x30\n\t"        /* context */
                   "bl " __ASM_NAME("dispatch_apc") "\n\t"
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
__ASM_GLOBAL_FUNC( "#KiUserCallbackDispatcher",
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


/**************************************************************************
 *              RtlIsEcCode (NTDLL.@)
 */
BOOLEAN WINAPI RtlIsEcCode( const void *ptr )
{
    const UINT64 *map = (const UINT64 *)NtCurrentTeb()->Peb->EcCodeBitMap;
    ULONG_PTR page = (ULONG_PTR)ptr / page_size;
    return (map[page / 64] >> (page & 63)) & 1;
}


/**********************************************************************
 *              RtlVirtualUnwind   (NTDLL.@)
 */
PVOID WINAPI RtlVirtualUnwind( ULONG type, ULONG_PTR base, ULONG_PTR pc,
                               RUNTIME_FUNCTION *func, CONTEXT *context,
                               PVOID *handler_data, ULONG_PTR *frame_ret,
                               KNONVOLATILE_CONTEXT_POINTERS *ctx_ptr )
{
    if (RtlIsEcCode( (const void *)pc ))
    {
        ARM64_RUNTIME_FUNCTION *arm_func = (ARM64_RUNTIME_FUNCTION *)func;
        ARM64_NT_CONTEXT arm_context;
        KNONVOLATILE_CONTEXT_POINTERS_ARM64 arm_ctx_ptr; /* TODO: convert? needs test */
        void *ptr;
        context_x64_to_arm( &arm_context, context );
        ptr = virtual_unwind_arm64( type, base, pc, arm_func, &arm_context, handler_data, frame_ret, &arm_ctx_ptr );
        context_arm_to_x64( context, &arm_context );
        if ((context->ContextFlags & CONTEXT_AMD64_UNWOUND_TO_CALL) == CONTEXT_AMD64_UNWOUND_TO_CALL &&
            !RtlIsEcCode( (const void *)context->Rip ))
	{
            context->ContextFlags &= ~CONTEXT_AMD64_UNWOUND_TO_CALL;
            if (frame_ret) *frame_ret -= 8;
	}
        return ptr;
    }
    else
    {
        return virtual_unwind_x86_64( type, base, pc, func, context, handler_data, frame_ret, ctx_ptr );
    }
}

/***********************************************************************
 *                RtlCaptureContext (NTDLL.@)
 */
// TODO: tests
void __attribute__((naked)) RtlCaptureContext( CONTEXT *context )
{
    asm( "str xzr,  [x0, #0x80]\n\t" /* context->X0 */
         "stp x1,   x27, [x0, #0x88]\n\t" /* context->X1, context->X27 */
         "mov x1,   sp\n\t"
         "stp x1,   x29, [x0, #0x98]\n\t" /* context->Sp, context->Fp */
         "stp x25,  x26, [x0, #0xa8]\n\t" /* context->X25, context->X26 */
         "stp x2,   x3,  [x0, #0xb8]\n\t" /* context->X2, context->X3 */
         "stp x4,   x5,  [x0, #0xc8]\n\t" /* context->X4, context->X5 */
         "stp x19,  x20, [x0, #0xd8]\n\t" /* context->X19, context->X20 */
         "stp x21,  x22, [x0, #0xe8]\n\t" /* context->X21, context->X22 */
         "str x30,      [x0, #0xf8]\n\t" /* context->Pc */

         "mov x1,   #0x27f\n\t"
         /* context->AMD64_{ControlWord,StatusWord,TagWord,Reserved1,ErrorOpcode,ErrorOffset,ErrorSelector,Reserved2} */
         "stp x1,   xzr, [x0, #0x100]\n\t"
         "mov w1,   #0x1f80\n\t"
         "stp xzr,  x1,  [x0, #0x110];\n\t" /* context->AMD64_{DataOffset,DataSelector,Reserved3,MxCsr,MxCsr_Mask} */
         "str w1,   [x0, #0x34];\n\t" /* context->AMD64_MxCsr_copy */
         "str xzr,  [x0, #0x120];\n\t" /* context->Lr */

         "strh w16, [x0, #0x128]\n\t" /* context->X16_0 */
         "str  x6,  [x0, #0x130]\n\t" /* context->X6 */
         "lsr  x16, x16, 16\n\t"
         "strh w16, [x0, #0x138]\n\t" /* context->X16_1 */
         "str  x7,  [x0, #0x140]\n\t" /* context->X7 */
         "lsr  x16, x16, 16\n\t"
         "strh w16, [x0, #0x148]\n\t" /* context->X16_2 */
         "str  x9,  [x0, #0x150]\n\t" /* context->X9 */
         "lsr  x16, x16, 16\n\t"
         "strh w16, [x0, #0x158]\n\t" /* context->X16_3 */
         "str  x10, [x0, #0x160]\n\t" /* context->X10 */
         "strh w17, [x0, #0x168]\n\t" /* context->X17_0 */
         "str  x11, [x0, #0x170]\n\t" /* context->X11 */
         "lsr  x17, x17, 16\n\t"
         "strh w17, [x0, #0x178]\n\t" /* context->X17_1 */
         "str  x12, [x0, #0x180]\n\t" /* context->X12 */
         "lsr  x17, x17, 16\n\t"
         "strh w17, [x0, #0x188]\n\t" /* context->X17_2 */
         "str  x15, [x0, #0x190]\n\t" /* context->X15 */
         "lsr  x17, x17, 16\n\t"
         "strh w17, [x0, #0x198]\n\t" /* context->X17_3 */
         "stp  q0,  q1,  [x0, #0x1a0]\n\t" /* context->V[0-1] */
         "stp  q2,  q3,  [x0, #0x1c0]\n\t" /* context->V[2-3] */
         "stp  q4,  q5,  [x0, #0x1e0]\n\t" /* context->V[4-5] */
         "stp  q6,  q7,  [x0, #0x200]\n\t" /* context->V[6-7] */
         "stp  q8,  q9,  [x0, #0x220]\n\t" /* context->V[8-9] */
         "stp  q10, q11, [x0, #0x240]\n\t" /* context->V[10-11] */
         "stp  q12, q13, [x0, #0x260]\n\t" /* context->V[12-13] */
         "stp  q14, q15, [x0, #0x280]\n\t" /* context->V[14-15] */
         "mov  x1,  #0x100000\n\t" /* CONTEXT_AMD64 */
         "movk x1,  #0xb\n\t" /* CONTEXT_AMD64_CONTROL | CONTEXT_AMD64_INTEGER | CONTEXT_AMD64_FLOATING_POINT */
         "str  w1,  [x0, #0x30]\n\t" /* context->ContextFlags */
         "ret" );
}

static int code_match( BYTE *code, const BYTE *seq, size_t len )
{
    for ( ; len; len--, code++, seq++) if (*seq && *code != *seq) return 0;
    return 1;
}

void *check_call( void **target, void *exit_thunk, void *dest )
{
    static const BYTE jmp_sequence[] =
    {
        0xff, 0x25              /* jmp *xxx(%rip) */
    };
    static const BYTE fast_forward_sequence[] =
    {
        0x48, 0x8b, 0xc4,       /* mov  %rsp,%rax */
        0x48, 0x89, 0x58, 0x20, /* mov  %rbx,0x20(%rax) */
        0x55,                   /* push %rbp */
        0x5d,                   /* pop  %rbp */
        0xe9                    /* jmp  arm_code */
    };
    static const BYTE syscall_sequence[] =
    {
        0x4c, 0x8b, 0xd1,       /* mov  %rcx,%r10 */
        0xb8, 0, 0, 0, 0,       /* mov  $xxx,%eax */
        0xf6, 0x04, 0x25, 0x08, /* testb $0x1,0x7ffe0308 */
        0x03, 0xfe, 0x7f, 0x01,
        0x75, 0x03,             /* jne 1f */
        0x0f, 0x05,             /* syscall */
        0xc3,                   /* ret */
        0xcd, 0x2e,             /* 1: int $0x2e */
        0xc3                    /* ret */
    };

    for (;;)
    {
        if (dest == __wine_unix_call_dispatcher) return dest;
        if (RtlIsEcCode( dest )) return dest;
        if (code_match( dest, jmp_sequence, sizeof(jmp_sequence) ))
        {
            int *off_ptr = (int *)((char *)dest + sizeof(jmp_sequence));
            void **addr_ptr = (void **)((char *)(off_ptr + 1) + *off_ptr);
            dest = *addr_ptr;
            continue;
        }
        if (!((ULONG_PTR)dest & 15))  /* fast-forward and syscall thunks are always aligned */
        {
            if (code_match( dest, fast_forward_sequence, sizeof(fast_forward_sequence) ))
            {
                int *off_ptr = (int *)((char *)dest + sizeof(fast_forward_sequence));
                return (char *)(off_ptr + 1) + *off_ptr;
            }
            if (code_match( dest, syscall_sequence, sizeof(syscall_sequence) ))
            {
                ULONG id = ((ULONG *)dest)[1];
                if (id < ARRAY_SIZE(arm64ec_syscalls)) return arm64ec_syscalls[id];
            }
        }
        *target = dest;
        return exit_thunk;
    }
}

static void __attribute__((naked)) arm64x_check_call(void)
{
    asm( "stp x29, x30, [sp,#-0xb0]!\n\t"
         "mov x29, sp\n\t"
         "stp x0, x1,   [sp, #0x10]\n\t"
         "stp x2, x3,   [sp, #0x20]\n\t"
         "stp x4, x5,   [sp, #0x30]\n\t"
         "stp x6, x7,   [sp, #0x40]\n\t"
         "stp x8, x9,   [sp, #0x50]\n\t"
         "stp x10, x15, [sp, #0x60]\n\t"
         "stp d0, d1,   [sp, #0x70]\n\t"
         "stp d2, d3,   [sp, #0x80]\n\t"
         "stp d4, d5,   [sp, #0x90]\n\t"
         "stp d6, d7,   [sp, #0xa0]\n\t"
         "add x0, sp, #0x58\n\t"  /* x9 = &target */
         "mov x1, x10\n\t"        /* x10 = exit_thunk */
         "mov x2, x11\n\t"        /* x11 = dest */
         "bl " __ASM_NAME("check_call") "\n\t"
         "mov x11, x0\n\t"
         "ldp x0, x1,   [sp, #0x10]\n\t"
         "ldp x2, x3,   [sp, #0x20]\n\t"
         "ldp x4, x5,   [sp, #0x30]\n\t"
         "ldp x6, x7,   [sp, #0x40]\n\t"
         "ldp x8, x9,   [sp, #0x50]\n\t"
         "ldp x10, x15, [sp, #0x60]\n\t"
         "ldp d0, d1,   [sp, #0x70]\n\t"
         "ldp d2, d3,   [sp, #0x80]\n\t"
         "ldp d4, d5,   [sp, #0x90]\n\t"
         "ldp d6, d7,   [sp, #0xa0]\n\t"
         "ldp x29, x30, [sp], #0xb0\n\t"
         "ret" );
}


/**************************************************************************
 *		__chkstk (NTDLL.@)
 *
 * Supposed to touch all the stack pages, but we shouldn't need that.
 */
void __attribute__((naked)) __chkstk(void)
{
    asm( "ret" );
}


/**************************************************************************
 *		__chkstk_arm64ec (NTDLL.@)
 *
 * Supposed to touch all the stack pages, but we shouldn't need that.
 */
void __attribute__((naked)) __chkstk_arm64ec(void)
{
    asm( "ret" );
}

/**********************************************************************
 *           call_Consolidate_callback
 *
 * Wrapper function to call a consolidate callback from a fake frame.
 * If the callback executes RtlUnwindEx (like for example done in C++ handlers),
 * we have to skip all frames which were already processed. To do that we
 * trick the unwinding functions into thinking the call came from the specified
 * context.
 */
void *consolidate_callback_wrapper( EXCEPTION_RECORD *rec, void *(CALLBACK *callback)(EXCEPTION_RECORD *) )
{
    return callback( rec );
}

void *__attribute__((naked)) call_consolidate_callback( CONTEXT *context,
                                                        void *(CALLBACK *callback)(EXCEPTION_RECORD *),
                                                        EXCEPTION_RECORD *rec)
{
    asm( __ASM_SEH(".seh_proc call_consolidate_callback\n\t")
         "stp x29, x30, [sp, #-0x20]!\n\t"
          __ASM_SEH(".seh_nop\n\t")
          "stp x1,  x2,  [sp, #0x10]\n\t"
          __ASM_SEH(".seh_nop\n\t")
          "mov x29, sp\n\t"
          __ASM_SEH(".seh_nop\n\t")
          /* Memcpy the context onto the stack */
          "sub sp, sp, #0x4d0\n\t"
          __ASM_SEH(".seh_nop\n\t")
          "mov x1,  x0\n\t"
          __ASM_SEH(".seh_nop\n\t")
          "mov x0,  sp\n\t"
          __ASM_SEH(".seh_nop\n\t")
          "mov x2,  #0x4d0\n\t"
          __ASM_SEH(".seh_nop\n\t")
          "bl " __ASM_NAME("memcpy") "\n\t"
          __ASM_SEH(".seh_ec_context\n\t")
          __ASM_SEH(".seh_endprologue\n\t")
          "ldp x1,  x2,  [x29, #0x10]\n\t"
          "mov x0,  x2\n\t"
          "bl " __ASM_NAME("consolidate_callback_wrapper") "\n\t"
          "mov sp,  x29\n\t"
          "ldp x29, x30, [sp], #0x20\n\t"
          "ret\n\t"
          __ASM_SEH(".seh_endproc") );
}

void context_restore_from_jmpbuf( CONTEXT *context, void *buf )
{
    struct MSVCRT_JUMP_BUFFER *jmp = (struct MSVCRT_JUMP_BUFFER *)buf;
    context->Rbx   = jmp->Rbx;
    context->Rsp   = jmp->Rsp;
    context->Rbp   = jmp->Rbp;
    context->Rsi   = jmp->Rsi;
    context->Rdi   = jmp->Rdi;
    context->R12   = jmp->R12;
    context->R13   = jmp->R13;
    context->R14   = jmp->R14;
    context->R15   = jmp->R15;
    context->Rip   = jmp->Rip;
    context->Xmm6  = jmp->Xmm6;
    context->Xmm7  = jmp->Xmm7;
    context->Xmm8  = jmp->Xmm8;
    context->Xmm9  = jmp->Xmm9;
    context->Xmm10 = jmp->Xmm10;
    context->Xmm11 = jmp->Xmm11;
    context->Xmm12 = jmp->Xmm12;
    context->Xmm13 = jmp->Xmm13;
    context->Xmm14 = jmp->Xmm14;
    context->Xmm15 = jmp->Xmm15;
    context->MxCsr = jmp->MxCsr;
    context->FltSave.MxCsr = jmp->MxCsr;
    context->FltSave.ControlWord = jmp->FpCsr;
}

void context_trace_gprs( CONTEXT *context )
{
    TRACE(" rax=%016I64x rbx=%016I64x rcx=%016I64x rdx=%016I64x\n",
          context->Rax, context->Rbx, context->Rcx, context->Rdx );
    TRACE(" rsi=%016I64x rdi=%016I64x rbp=%016I64x rsp=%016I64x\n",
          context->Rsi, context->Rdi, context->Rbp, context->Rsp );
    TRACE("  r8=%016I64x  r9=%016I64x r10=%016I64x r11=%016I64x\n",
          context->R8, context->R9, context->R10, context->R11 );
    TRACE(" r12=%016I64x r13=%016I64x r14=%016I64x r15=%016I64x\n",
          context->R12, context->R13, context->R14, context->R15 );
}

__ASM_GLOBAL_FUNC( "#__C_ExecuteExceptionFilter",
                   "stp x29, x30, [sp, #-136]!\n\t"
                   __ASM_SEH(".seh_save_fplr_x 128\n\t")
                   "stp x19, x20, [sp, #16]\n\t"
                   __ASM_SEH(".seh_save_regp x19, 16\n\t")
                   "stp x21, x22, [sp, #32]\n\t"
                   __ASM_SEH(".seh_save_regp x21, 32\n\t")
                   "stp x25, x26, [sp, #48]\n\t"
                   __ASM_SEH(".seh_save_regp x25, 48\n\t")
                   "str x27,      [sp, #64]\n\t"
                   __ASM_SEH(".seh_save_reg  x27, 64\n\t")
                   "stp d8,  d9,  [sp, #72]\n\t"
                   __ASM_SEH(".seh_save_fregp d8,  72\n\t")
                   "stp d10, d11, [sp, #88]\n\t"
                   __ASM_SEH(".seh_save_fregp d10, 88\n\t")
                   "stp d12, d13, [sp, #104]\n\t"
                   __ASM_SEH(".seh_save_fregp d12, 104\n\t")
                   "stp d14, d15, [sp, #120]\n\t"
                   __ASM_SEH(".seh_save_fregp d14, 120\n\t")
                   "mov x29, sp\n\t"
                   __ASM_SEH(".seh_set_fp\n\t")
                   __ASM_SEH(".seh_endprologue\n\t")

                   "ldp x19, x20, [x3, #0]\n\t"
                   "ldp x21, x22, [x3, #16]\n\t"
                   /* X23/X24 are reserved for EC */
                   "ldp x25, x26, [x3, #48]\n\t"
                   "ldr x27,      [x3, #64]\n\t"
                   /* X28 is reserved for EC */
                   /* Overwrite the frame parameter with Fp from the
                    * nonvolatile regs */
                   "ldr x1,  [x3, #80]\n\t"
                   "ldp d8,  d9,  [x3, #88]\n\t"
                   "ldp d10, d11, [x3, #104]\n\t"
                   "ldp d12, d13, [x3, #120]\n\t"
                   "ldp d14, d15, [x3, #136]\n\t"
                   "blr x2\n\t"
                   "ldp x19, x20, [sp, #16]\n\t"
                   "ldp x21, x22, [sp, #32]\n\t"
                   "ldp x25, x26, [sp, #48]\n\t"
                   "ldr x27,      [sp, #64]\n\t"
                   "ldp d8,  d9,  [sp, #72]\n\t"
                   "ldp d10, d11, [sp, #88]\n\t"
                   "ldp d12, d13, [sp, #104]\n\t"
                   "ldp d14, d15, [sp, #120]\n\t"
                   "ldp x29, x30, [sp], #136\n\t"
                   "ret")

/* This is, implementation wise, identical to __C_ExecuteExceptionFilter. */
__ASM_GLOBAL_FUNC( "#__C_ExecuteTerminationHandler",
                   "b " __ASM_NAME("#__C_ExecuteExceptionFilter") "\n\t");

/***********************************************************************
 *           RtlUserThreadStart (NTDLL.@)
 */
void WINAPI RtlUserThreadStart( PRTL_THREAD_START_ROUTINE entry, void *arg )
{
    __TRY
    {
        pBaseThreadInitThunk( 0, (LPTHREAD_START_ROUTINE)entry, arg );
    }
    __EXCEPT(call_unhandled_exception_filter)
    {
        NtTerminateProcess( GetCurrentProcess(), GetExceptionCode() );
    }
    __ENDTRY
}


/******************************************************************
 *		LdrInitializeThunk (NTDLL.@)
 */
void WINAPI LdrInitializeThunk( CONTEXT *arm_context, ULONG_PTR unk2, ULONG_PTR unk3, ULONG_PTR unk4 )
{
    CONTEXT context;

    if (!__os_arm64x_check_call)
    {
        __os_arm64x_check_call = arm64x_check_call;
        __os_arm64x_check_icall = arm64x_check_call;
        __os_arm64x_check_icall_cfg = arm64x_check_call;
        __os_arm64x_get_x64_information = LdrpGetX64Information;
        __os_arm64x_set_x64_information = LdrpSetX64Information;
    }

    context_arm_to_x64( &context, (ARM64_NT_CONTEXT *)arm_context );
    loader_init( &context, (void **)&context.Rcx );
    TRACE_(relay)( "\1Starting thread proc %p (arg=%p)\n", (void *)context.Rcx, (void *)context.Rdx );
    NtContinue( &context, TRUE );
}

/***********************************************************************
 *                RtlRaiseException (NTDLL.@)
 */
// TODO: is it better to capture ec context here?
void __attribute__((naked)) RtlRaiseException( struct _EXCEPTION_RECORD * rec)
{
    asm( __ASM_SEH(".seh_proc RtlRaiseException\n\t")
         "sub sp, sp, #0x3b0\n\t" /* 0x390 (context) + 0x20 */
         "stp x29, x30, [sp]\n\t"
         __ASM_SEH(".seh_stackalloc 0x3b0\n\t")
         __ASM_SEH(".seh_save_fplr 0\n\t")
         __ASM_SEH(".seh_endprologue\n\t")
         "mov x29, sp\n\t"
         "str x0,  [sp, #0x10]\n\t"
         "add x0,  sp, #0x20\n\t"
         "bl " __ASM_NAME("capture_arm64_context") "\n\t"
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
         "bl " __ASM_NAME("dispatch_exception_ec") "\n"
         "1:\tmov  x2, #1\n\t"
         "bl " __ASM_NAME("syscall_NtRaiseException") "\n\t"
         "bl " __ASM_NAME("RtlRaiseStatus") "\n\t" /* does not return */
          __ASM_SEH(".seh_endproc\n\t") );
}



/**********************************************************************
 *              DbgBreakPoint   (NTDLL.@)
 */
void __attribute__((naked)) DbgBreakPoint(void)
{
    asm( "brk #0xf000; ret" );
}


/**********************************************************************
 *              DbgUserBreakPoint   (NTDLL.@)
 */
void __attribute__((naked)) DbgUserBreakPoint(void)
{
    asm( "brk #0xf000; ret" );
}

#endif  /* __arm64ec__ */
