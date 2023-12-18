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

#if defined(__aarch64__) || defined(__arm64ec__)

#include <stdlib.h>
#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/exception.h"
#include "ntdll_misc.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(seh);

/***********************************************************************
 * Definitions for Win32 unwind tables
 */

struct unwind_info
{
    DWORD function_length : 18;
    DWORD version : 2;
    DWORD x : 1;
    DWORD e : 1;
    DWORD epilog : 5;
    DWORD codes : 5;
};

struct unwind_info_ext
{
    WORD epilog;
    BYTE codes;
    BYTE reserved;
};

struct unwind_info_epilog
{
    DWORD offset : 18;
    DWORD res : 4;
    DWORD index : 10;
};

static const BYTE unwind_code_len[256] =
{
/* 00 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 20 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 40 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 60 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 80 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* a0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* c0 */ 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
/* e0 */ 4,1,2,1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
};

/***********************************************************************
 *           get_sequence_len
 */
static unsigned int get_sequence_len( BYTE *ptr, BYTE *end )
{
    unsigned int ret = 0;

    while (ptr < end)
    {
        if (*ptr == 0xe4 || *ptr == 0xe5) break;
        ptr += unwind_code_len[*ptr];
        ret++;
    }
    return ret;
}


/***********************************************************************
 *           restore_regs
 */
static void restore_regs( int reg, int count, int pos, ARM64_NT_CONTEXT *context,
                          KNONVOLATILE_CONTEXT_POINTERS_ARM64 *ptrs )
{
    int i, offset = max( 0, pos );
    for (i = 0; i < count; i++)
    {
        if (ptrs && reg + i >= 19) (&ptrs->X19)[reg + i - 19] = (DWORD64 *)context->Sp + i + offset;
        context->X[reg + i] = ((DWORD64 *)context->Sp)[i + offset];
    }
    if (pos < 0) context->Sp += -8 * pos;
}


/***********************************************************************
 *           restore_fpregs
 */
static void restore_fpregs( int reg, int count, int pos, ARM64_NT_CONTEXT *context,
                            KNONVOLATILE_CONTEXT_POINTERS_ARM64 *ptrs )
{
    int i, offset = max( 0, pos );
    for (i = 0; i < count; i++)
    {
        if (ptrs && reg + i >= 8) (&ptrs->D8)[reg + i - 8] = (DWORD64 *)context->Sp + i + offset;
        context->V[reg + i].D[0] = ((double *)context->Sp)[i + offset];
    }
    if (pos < 0) context->Sp += -8 * pos;
}

static void restore_simdregs( int reg, int count, int pos, ARM64_NT_CONTEXT *context,
                              KNONVOLATILE_CONTEXT_POINTERS_ARM64 *ptrs )
{
    int i, offset = max( 0, pos );
    for (i = 0; i < count; i++)
    {
        DWORD64 *reg_ptr = (DWORD64 *)context->Sp + (i + offset) * 2;
        if (ptrs && reg + i >= 8) (&ptrs->D8)[reg + i - 8] = reg_ptr;
        memcpy(&context->V[reg + i], reg_ptr, sizeof(context->V[reg + i]));
    }
    if (pos < 0) context->Sp += -16 * pos;
}

static void do_save_any_reg( int save_count, BYTE *ptr, ARM64_NT_CONTEXT *context,
                             KNONVOLATILE_CONTEXT_POINTERS_ARM64 *ptrs)
{
    BOOL writeback = !!(ptr[1] & 0x20);
    BOOL paired = !!(ptr[1] & 0x40);
    // 0 -> Xn, 1 -> Dn, 2 -> Qn, 3-> Reserved
    int reg_kind = (ptr[2] & 0xc0) >> 6;
    int reg = ptr[1] & 0x1f;
    int stack_offset = ptr[2] & 0x3f;


    if ((paired && save_count != 2) || ((ptr[1] & 0x80) != 0) || (reg_kind == 3))
    {
        ERR( "Invalid save_any_reg format" );
        return;
    }

    if (!paired)
        save_count = 1;

    if (writeback) stack_offset = (stack_offset + 1) * -1;
    if ((writeback || paired) && reg_kind != 2) stack_offset *= 2;

    switch (reg_kind)
    {
        case 0:
            restore_regs( reg, save_count, stack_offset, context, ptrs );
            break;
        case 1:
            restore_fpregs( reg, save_count, stack_offset, context, ptrs );
            break;
        case 2:
            restore_simdregs( reg, save_count, stack_offset, context, ptrs );
            break;
    }
}

static void do_pac_auth( ARM64_NT_CONTEXT *context )
{
    register DWORD64 x17 __asm__( "x17" ) = context->Lr;
    register DWORD64 x16 __asm__( "x16" ) = context->Sp;

    /* This is the autib1716 instruction. The hint instruction is used here
     * as gcc does not assemble autib1716 for pre armv8.3a targets. For
     * pre-armv8.3a targets, this is just treated as a hint instruction, which
     * is ignored. */
    __asm__( "hint 0xe" : "+r"(x17) : "r"(x16) );

    context->Lr = x17;
}

/***********************************************************************
 *           process_unwind_codes
 */
static void process_unwind_codes( BYTE *ptr, BYTE *end, ARM64_NT_CONTEXT *context,
                                  KNONVOLATILE_CONTEXT_POINTERS_ARM64 *ptrs, int skip )
{
    unsigned int val, len, save_next = 2;

    /* skip codes */
    while (ptr < end && skip)
    {
        if (*ptr == 0xe4 || *ptr == 0xe5) break;
        ptr += unwind_code_len[*ptr];
        skip--;
    }

    while (ptr < end)
    {
        if ((len = unwind_code_len[*ptr]) > 1)
        {
            if (ptr + len > end) break;
            val = ptr[0] * 0x100 + ptr[1];
        }
        else val = *ptr;

        if (*ptr < 0x20)  /* alloc_s */
            context->Sp += 16 * (val & 0x1f);
        else if (*ptr < 0x40)  /* save_r19r20_x */
            restore_regs( 19, save_next, -(val & 0x1f), context, ptrs );
        else if (*ptr < 0x80) /* save_fplr */
            restore_regs( 29, 2, val & 0x3f, context, ptrs );
        else if (*ptr < 0xc0)  /* save_fplr_x */
            restore_regs( 29, 2, -(val & 0x3f) - 1, context, ptrs );
        else if (*ptr < 0xc8)  /* alloc_m */
            context->Sp += 16 * (val & 0x7ff);
        else if (*ptr < 0xcc)  /* save_regp */
            restore_regs( 19 + ((val >> 6) & 0xf), save_next, val & 0x3f, context, ptrs );
        else if (*ptr < 0xd0)  /* save_regp_x */
            restore_regs( 19 + ((val >> 6) & 0xf), save_next, -(val & 0x3f) - 1, context, ptrs );
        else if (*ptr < 0xd4)  /* save_reg */
            restore_regs( 19 + ((val >> 6) & 0xf), 1, val & 0x3f, context, ptrs );
        else if (*ptr < 0xd6)  /* save_reg_x */
            restore_regs( 19 + ((val >> 5) & 0xf), 1, -(val & 0x1f) - 1, context, ptrs );
        else if (*ptr < 0xd8)  /* save_lrpair */
        {
            restore_regs( 19 + 2 * ((val >> 6) & 0x7), 1, val & 0x3f, context, ptrs );
            restore_regs( 30, 1, (val & 0x3f) + 1, context, ptrs );
        }
        else if (*ptr < 0xda)  /* save_fregp */
            restore_fpregs( 8 + ((val >> 6) & 0x7), save_next, val & 0x3f, context, ptrs );
        else if (*ptr < 0xdc)  /* save_fregp_x */
            restore_fpregs( 8 + ((val >> 6) & 0x7), save_next, -(val & 0x3f) - 1, context, ptrs );
        else if (*ptr < 0xde)  /* save_freg */
            restore_fpregs( 8 + ((val >> 6) & 0x7), 1, val & 0x3f, context, ptrs );
        else if (*ptr == 0xde)  /* save_freg_x */
            restore_fpregs( 8 + ((val >> 5) & 0x7), 1, -(val & 0x3f) - 1, context, ptrs );
        else if (*ptr == 0xe0)  /* alloc_l */
            context->Sp += 16 * ((ptr[1] << 16) + (ptr[2] << 8) + ptr[3]);
        else if (*ptr == 0xe1)  /* set_fp */
            context->Sp = context->Fp;
        else if (*ptr == 0xe2)  /* add_fp */
            context->Sp = context->Fp - 8 * (val & 0xff);
        else if (*ptr == 0xe3)  /* nop */
            /* nop */ ;
        else if (*ptr == 0xe4)  /* end */
            break;
        else if (*ptr == 0xe5)  /* end_c */
            break;
        else if (*ptr == 0xe6)  /* save_next */
        {
            save_next += 2;
            ptr += len;
            continue;
        }
        else if (*ptr == 0xe7)  /* save_any_reg */
        {
            do_save_any_reg( save_next, ptr, context, ptrs );
        }
        else if (*ptr == 0xe9)  /* MSFT_OP_MACHINE_FRAME */
        {
            context->Pc = ((DWORD64 *)context->Sp)[1];
            context->Sp = ((DWORD64 *)context->Sp)[0];
        }
        else if (*ptr == 0xea)  /* MSFT_OP_CONTEXT */
        {
            memcpy( context, (DWORD64 *)context->Sp, sizeof(ARM64_NT_CONTEXT) );
        }
        else if (*ptr == 0xfc)  /* pac_sign_lr */
        {
            do_pac_auth( context );
        }
        else
        {
            WARN( "unsupported code %02x\n", *ptr );
            return;
        }
        save_next = 2;
        ptr += len;
    }
}


/***********************************************************************
 *           unwind_packed_data
 */
static void *unwind_packed_data( ULONG_PTR base, ULONG_PTR pc, ARM64_RUNTIME_FUNCTION *func,
                                 ARM64_NT_CONTEXT *context, KNONVOLATILE_CONTEXT_POINTERS_ARM64 *ptrs )
{
    int i;
    unsigned int len, offset, skip = 0;
    unsigned int int_size = func->RegI * 8, fp_size = func->RegF * 8, regsave, local_size;
    unsigned int int_regs, fp_regs, saved_regs, local_size_regs;

    TRACE( "function %I64x-%I64x: len=%#x flag=%x regF=%u regI=%u H=%u CR=%u frame=%x\n",
           base + func->BeginAddress, base + func->BeginAddress + func->FunctionLength * 4,
           func->FunctionLength, func->Flag, func->RegF, func->RegI, func->H, func->CR, func->FrameSize );

    if (func->CR == 1) int_size += 8;
    if (func->RegF) fp_size += 8;

    regsave = ((int_size + fp_size + 8 * 8 * func->H) + 0xf) & ~0xf;
    local_size = func->FrameSize * 16 - regsave;

    int_regs = int_size / 8;
    fp_regs = fp_size / 8;
    saved_regs = regsave / 8;
    local_size_regs = local_size / 8;

    /* check for prolog/epilog */
    if (func->Flag == 1)
    {
        offset = ((pc - base) - func->BeginAddress) / 4;
        if (offset < 17 || offset >= func->FunctionLength - 15)
        {
            len = (int_size + 8) / 16 + (fp_size + 8) / 16;
            switch (func->CR)
            {
            case 2:
                len++; /* pacibsp */
                /* fall through */
            case 3:
                len++; /* mov x29,sp */
                len++; /* stp x29,lr,[sp,0] */
                if (local_size <= 512) break;
                /* fall through */
            case 0:
            case 1:
                if (local_size) len++;  /* sub sp,sp,#local_size */
                if (local_size > 4088) len++;  /* sub sp,sp,#4088 */
                break;
            }
            len += 4 * func->H;
            if (offset < len)  /* prolog */
            {
                skip = len - offset;
            }
            else if (offset >= func->FunctionLength - (len + 1))  /* epilog */
            {
                skip = offset - (func->FunctionLength - (len + 1));
            }
        }
    }

    if (!skip)
    {
        if (func->CR == 3 || func->CR == 2)
        {
            DWORD64 *fp = (DWORD64 *) context->Fp; /* X[29] */
            context->Sp = context->Fp;
            context->X[29] = fp[0];
            context->X[30] = fp[1];
        }
        context->Sp += local_size;
        if (fp_size) restore_fpregs( 8, fp_regs, int_regs, context, ptrs );
        if (func->CR == 1) restore_regs( 30, 1, int_regs - 1, context, ptrs );
        restore_regs( 19, func->RegI, -saved_regs, context, ptrs );
    }
    else
    {
        unsigned int pos = 0;

        switch (func->CR)
        {
        case 3:
        case 2:
            /* mov x29,sp */
            if (pos++ >= skip) context->Sp = context->Fp;
            if (local_size <= 512)
            {
                /* stp x29,lr,[sp,-#local_size]! */
                if (pos++ >= skip) restore_regs( 29, 2, -local_size_regs, context, ptrs );
                break;
            }
            /* stp x29,lr,[sp,0] */
            if (pos++ >= skip) restore_regs( 29, 2, 0, context, ptrs );
            /* fall through */
        case 0:
        case 1:
            if (!local_size) break;
            /* sub sp,sp,#local_size */
            if (pos++ >= skip) context->Sp += (local_size - 1) % 4088 + 1;
            if (local_size > 4088 && pos++ >= skip) context->Sp += 4088;
            break;
        }

        if (func->H) pos += 4;

        if (fp_size)
        {
            if (func->RegF % 2 == 0 && pos++ >= skip)
                /* str d%u,[sp,#fp_size] */
                restore_fpregs( 8 + func->RegF, 1, int_regs + fp_regs - 1, context, ptrs );
            for (i = (func->RegF + 1) / 2 - 1; i >= 0; i--)
            {
                if (pos++ < skip) continue;
                if (!i && !int_size)
                     /* stp d8,d9,[sp,-#regsave]! */
                    restore_fpregs( 8, 2, -saved_regs, context, ptrs );
                else
                     /* stp dn,dn+1,[sp,#offset] */
                    restore_fpregs( 8 + 2 * i, 2, int_regs + 2 * i, context, ptrs );
            }
        }

        if (func->RegI % 2)
        {
            if (pos++ >= skip)
            {
                /* stp xn,lr,[sp,#offset] */
                if (func->CR == 1) restore_regs( 30, 1, int_regs - 1, context, ptrs );
                /* str xn,[sp,#offset] */
                restore_regs( 18 + func->RegI, 1,
                              (func->RegI > 1) ? func->RegI - 1 : -saved_regs,
                              context, ptrs );
            }
        }
        else if (func->CR == 1)
        {
            /* str lr,[sp,#offset] */
            if (pos++ >= skip) restore_regs( 30, 1, func->RegI ? int_regs - 1 : -saved_regs, context, ptrs );
        }

        for (i = func->RegI / 2 - 1; i >= 0; i--)
        {
            if (pos++ < skip) continue;
            if (i)
                /* stp xn,xn+1,[sp,#offset] */
                restore_regs( 19 + 2 * i, 2, 2 * i, context, ptrs );
            else
                /* stp x19,x20,[sp,-#regsave]! */
                restore_regs( 19, 2, -saved_regs, context, ptrs );
        }
    }
    if (func->CR == 2) do_pac_auth( context );
    return NULL;
}


/***********************************************************************
 *           unwind_full_data
 */
static void *unwind_full_data( ULONG_PTR base, ULONG_PTR pc, ARM64_RUNTIME_FUNCTION *func,
                               ARM64_NT_CONTEXT *context, PVOID *handler_data, KNONVOLATILE_CONTEXT_POINTERS_ARM64 *ptrs )
{
    struct unwind_info *info;
    struct unwind_info_epilog *info_epilog;
    unsigned int i, codes, epilogs, len, offset;
    void *data;
    BYTE *end;

    info = (struct unwind_info *)((char *)base + func->UnwindData);
    data = info + 1;
    epilogs = info->epilog;
    codes = info->codes;
    if (!codes && !epilogs)
    {
        struct unwind_info_ext *infoex = data;
        codes = infoex->codes;
        epilogs = infoex->epilog;
        data = infoex + 1;
    }
    info_epilog = data;
    if (!info->e) data = info_epilog + epilogs;

    offset = ((pc - base) - func->BeginAddress) / 4;
    end = (BYTE *)data + codes * 4;

    TRACE( "function %I64x-%I64x: len=%#x ver=%u X=%u E=%u epilogs=%u codes=%u\n",
           base + func->BeginAddress, base + func->BeginAddress + info->function_length * 4,
           info->function_length, info->version, info->x, info->e, epilogs, codes * 4 );

    /* check for prolog */
    if (offset < codes * 4)
    {
        len = get_sequence_len( data, end );
        if (offset < len)
        {
            process_unwind_codes( data, end, context, ptrs, len - offset );
            return NULL;
        }
    }

    /* check for epilog */
    if (!info->e)
    {
        for (i = 0; i < epilogs; i++)
        {
            if (offset < info_epilog[i].offset) break;
            if (offset - info_epilog[i].offset < codes * 4 - info_epilog[i].index)
            {
                BYTE *ptr = (BYTE *)data + info_epilog[i].index;
                len = get_sequence_len( ptr, end );
                if (offset <= info_epilog[i].offset + len)
                {
                    process_unwind_codes( ptr, end, context, ptrs, offset - info_epilog[i].offset );
                    return NULL;
                }
            }
        }
    }
    else if (info->function_length - offset <= codes * 4 - epilogs)
    {
        BYTE *ptr = (BYTE *)data + epilogs;
        len = get_sequence_len( ptr, end ) + 1;
        if (offset >= info->function_length - len)
        {
            process_unwind_codes( ptr, end, context, ptrs, offset - (info->function_length - len) );
            return NULL;
        }
    }

    process_unwind_codes( data, end, context, ptrs, 0 );

    /* get handler since we are inside the main code */
    if (info->x)
    {
        DWORD *handler_rva = (DWORD *)data + codes;
        *handler_data = handler_rva + 1;
        return (char *)base + *handler_rva;
    }
    return NULL;
}

/**********************************************************************
 *              virtual_unwind_arm64
 */
PVOID virtual_unwind_arm64( ULONG type, ULONG_PTR base, ULONG_PTR pc,
                            ARM64_RUNTIME_FUNCTION *func, ARM64_NT_CONTEXT *context,
                            PVOID *handler_data, ULONG_PTR *frame_ret,
                            KNONVOLATILE_CONTEXT_POINTERS_ARM64 *ctx_ptr )
{
    void *handler;

    TRACE( "type %lx pc %I64x sp %I64x func %I64x\n", type, pc, context->Sp, base + func->BeginAddress );

    *handler_data = NULL;

    context->Pc = 0;
    if (func->Flag)
        handler = unwind_packed_data( base, pc, func, context, ctx_ptr );
    else
        handler = unwind_full_data( base, pc, func, context, handler_data, ctx_ptr );

    TRACE( "ret: lr=%I64x sp=%I64x handler=%p\n", context->Lr, context->Sp, handler );
    if (!context->Pc)
        context->Pc = context->Lr;
    context->ContextFlags |= CONTEXT_UNWOUND_TO_CALL;
    *frame_ret = context->Sp;
    return handler;
}

#endif // __aarch64__ || __arm64ec__
