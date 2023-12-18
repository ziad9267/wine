/*
 * NT exception handling routines
 *
 * Copyright 1999 Turchanov Sergey
 * Copyright 1999 Alexandre Julliard
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

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "ddk/wdm.h"
#include "wine/exception.h"
#include "wine/list.h"
#include "wine/debug.h"
#include "excpt.h"
#include "ntdll_misc.h"

WINE_DEFAULT_DEBUG_CHANNEL(seh);

typedef struct
{
    struct list                 entry;
    PVECTORED_EXCEPTION_HANDLER func;
    ULONG                       count;
} VECTORED_HANDLER;

static struct list vectored_exception_handlers = LIST_INIT(vectored_exception_handlers);
static struct list vectored_continue_handlers  = LIST_INIT(vectored_continue_handlers);

static RTL_CRITICAL_SECTION vectored_handlers_section;
static RTL_CRITICAL_SECTION_DEBUG critsect_debug =
{
    0, 0, &vectored_handlers_section,
    { &critsect_debug.ProcessLocksList, &critsect_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": vectored_handlers_section") }
};
static RTL_CRITICAL_SECTION vectored_handlers_section = { &critsect_debug, -1, 0, 0, 0, 0 };

static PRTL_EXCEPTION_FILTER unhandled_exception_filter;

const char *debugstr_exception_code( DWORD code )
{
    switch (code)
    {
    case CONTROL_C_EXIT: return "CONTROL_C_EXIT";
    case DBG_CONTROL_C: return "DBG_CONTROL_C";
    case DBG_PRINTEXCEPTION_C: return "DBG_PRINTEXCEPTION_C";
    case DBG_PRINTEXCEPTION_WIDE_C: return "DBG_PRINTEXCEPTION_WIDE_C";
    case EXCEPTION_ACCESS_VIOLATION: return "EXCEPTION_ACCESS_VIOLATION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_BREAKPOINT: return "EXCEPTION_BREAKPOINT";
    case EXCEPTION_DATATYPE_MISALIGNMENT: return "EXCEPTION_DATATYPE_MISALIGNMENT";
    case EXCEPTION_FLT_DENORMAL_OPERAND: return "EXCEPTION_FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO: return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT: return "EXCEPTION_FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION: return "EXCEPTION_FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW: return "EXCEPTION_FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK: return "EXCEPTION_FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW: return "EXCEPTION_FLT_UNDERFLOW";
    case EXCEPTION_GUARD_PAGE: return "EXCEPTION_GUARD_PAGE";
    case EXCEPTION_ILLEGAL_INSTRUCTION: return "EXCEPTION_ILLEGAL_INSTRUCTION";
    case EXCEPTION_IN_PAGE_ERROR: return "EXCEPTION_IN_PAGE_ERROR";
    case EXCEPTION_INT_DIVIDE_BY_ZERO: return "EXCEPTION_INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW: return "EXCEPTION_INT_OVERFLOW";
    case EXCEPTION_INVALID_DISPOSITION: return "EXCEPTION_INVALID_DISPOSITION";
    case EXCEPTION_INVALID_HANDLE: return "EXCEPTION_INVALID_HANDLE";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_PRIV_INSTRUCTION: return "EXCEPTION_PRIV_INSTRUCTION";
    case EXCEPTION_SINGLE_STEP: return "EXCEPTION_SINGLE_STEP";
    case EXCEPTION_STACK_OVERFLOW: return "EXCEPTION_STACK_OVERFLOW";
    case EXCEPTION_WINE_ASSERTION: return "EXCEPTION_WINE_ASSERTION";
    case EXCEPTION_WINE_CXX_EXCEPTION: return "EXCEPTION_WINE_CXX_EXCEPTION";
    case EXCEPTION_WINE_NAME_THREAD: return "EXCEPTION_WINE_NAME_THREAD";
    case EXCEPTION_WINE_STUB: return "EXCEPTION_WINE_STUB";
    case RPC_S_SERVER_UNAVAILABLE: return "RPC_S_SERVER_UNAVAILABLE";
    }
    return "unknown";
}


static VECTORED_HANDLER *add_vectored_handler( struct list *handler_list, ULONG first,
                                               PVECTORED_EXCEPTION_HANDLER func )
{
    VECTORED_HANDLER *handler = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(*handler) );
    if (handler)
    {
        handler->func = RtlEncodePointer( func );
        handler->count = 1;
        RtlEnterCriticalSection( &vectored_handlers_section );
        if (first) list_add_head( handler_list, &handler->entry );
        else list_add_tail( handler_list, &handler->entry );
        RtlLeaveCriticalSection( &vectored_handlers_section );
    }
    return handler;
}


static ULONG remove_vectored_handler( struct list *handler_list, VECTORED_HANDLER *handler )
{
    struct list *ptr;
    ULONG ret = FALSE;

    RtlEnterCriticalSection( &vectored_handlers_section );
    LIST_FOR_EACH( ptr, handler_list )
    {
        VECTORED_HANDLER *curr_handler = LIST_ENTRY( ptr, VECTORED_HANDLER, entry );
        if (curr_handler == handler)
        {
            if (!--curr_handler->count) list_remove( ptr );
            else handler = NULL;  /* don't free it yet */
            ret = TRUE;
            break;
        }
    }
    RtlLeaveCriticalSection( &vectored_handlers_section );
    if (ret) RtlFreeHeap( GetProcessHeap(), 0, handler );
    return ret;
}


/**********************************************************************
 *           call_vectored_handlers
 *
 * Call the vectored handlers chain.
 */
LONG call_vectored_handlers( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    struct list *ptr;
    LONG ret = EXCEPTION_CONTINUE_SEARCH;
    EXCEPTION_POINTERS except_ptrs;
    PVECTORED_EXCEPTION_HANDLER func;
    VECTORED_HANDLER *handler, *to_free = NULL;

    except_ptrs.ExceptionRecord = rec;
    except_ptrs.ContextRecord = context;

    RtlEnterCriticalSection( &vectored_handlers_section );
    ptr = list_head( &vectored_exception_handlers );
    while (ptr)
    {
        handler = LIST_ENTRY( ptr, VECTORED_HANDLER, entry );
        handler->count++;
        func = RtlDecodePointer( handler->func );
        RtlLeaveCriticalSection( &vectored_handlers_section );
        RtlFreeHeap( GetProcessHeap(), 0, to_free );
        to_free = NULL;

        TRACE( "calling handler at %p code=%lx flags=%lx\n",
               func, rec->ExceptionCode, rec->ExceptionFlags );
        ret = func( &except_ptrs );
        TRACE( "handler at %p returned %lx\n", func, ret );

        RtlEnterCriticalSection( &vectored_handlers_section );
        ptr = list_next( &vectored_exception_handlers, ptr );
        if (!--handler->count)  /* removed during execution */
        {
            list_remove( &handler->entry );
            to_free = handler;
        }
        if (ret == EXCEPTION_CONTINUE_EXECUTION) break;
    }
    RtlLeaveCriticalSection( &vectored_handlers_section );
    RtlFreeHeap( GetProcessHeap(), 0, to_free );
    return ret;
}


/*******************************************************************
 *		raise_status
 *
 * Implementation of RtlRaiseStatus with a specific exception record.
 */
void DECLSPEC_NORETURN raise_status( NTSTATUS status, EXCEPTION_RECORD *rec )
{
    EXCEPTION_RECORD ExceptionRec;

    ExceptionRec.ExceptionCode    = status;
    ExceptionRec.ExceptionFlags   = EH_NONCONTINUABLE;
    ExceptionRec.ExceptionRecord  = rec;
    ExceptionRec.NumberParameters = 0;
    for (;;) RtlRaiseException( &ExceptionRec );  /* never returns */
}


/***********************************************************************
 *            RtlRaiseStatus  (NTDLL.@)
 *
 * Raise an exception with ExceptionCode = status
 */
void DECLSPEC_NORETURN WINAPI RtlRaiseStatus( NTSTATUS status )
{
    raise_status( status, NULL );
}


/*******************************************************************
 *		KiRaiseUserExceptionDispatcher  (NTDLL.@)
 */
NTSTATUS WINAPI KiRaiseUserExceptionDispatcher(void)
{
    DWORD code = NtCurrentTeb()->ExceptionCode;
    EXCEPTION_RECORD rec = { code };
    RtlRaiseException( &rec );
    return code;
}


/*******************************************************************
 *         RtlAddVectoredContinueHandler   (NTDLL.@)
 */
PVOID WINAPI RtlAddVectoredContinueHandler( ULONG first, PVECTORED_EXCEPTION_HANDLER func )
{
    return add_vectored_handler( &vectored_continue_handlers, first, func );
}


/*******************************************************************
 *         RtlRemoveVectoredContinueHandler   (NTDLL.@)
 */
ULONG WINAPI RtlRemoveVectoredContinueHandler( PVOID handler )
{
    return remove_vectored_handler( &vectored_continue_handlers, handler );
}


/*******************************************************************
 *         RtlAddVectoredExceptionHandler   (NTDLL.@)
 */
PVOID WINAPI DECLSPEC_HOTPATCH RtlAddVectoredExceptionHandler( ULONG first, PVECTORED_EXCEPTION_HANDLER func )
{
    return add_vectored_handler( &vectored_exception_handlers, first, func );
}


/*******************************************************************
 *         RtlRemoveVectoredExceptionHandler   (NTDLL.@)
 */
ULONG WINAPI RtlRemoveVectoredExceptionHandler( PVOID handler )
{
    return remove_vectored_handler( &vectored_exception_handlers, handler );
}


/*******************************************************************
 *         RtlSetUnhandledExceptionFilter   (NTDLL.@)
 */
void WINAPI RtlSetUnhandledExceptionFilter( PRTL_EXCEPTION_FILTER filter )
{
    unhandled_exception_filter = filter;
}


/*******************************************************************
 *         call_unhandled_exception_filter
 */
LONG WINAPI call_unhandled_exception_filter( PEXCEPTION_POINTERS eptr )
{
    if (!unhandled_exception_filter) return EXCEPTION_CONTINUE_SEARCH;
    return unhandled_exception_filter( eptr );
}

/*******************************************************************
 *         call_unhandled_exception_handler
 */
EXCEPTION_DISPOSITION WINAPI call_unhandled_exception_handler( EXCEPTION_RECORD *rec, void *frame,
                                                               CONTEXT *context, void *dispatch )
{
    EXCEPTION_POINTERS ep = { rec, context };

    switch (call_unhandled_exception_filter( &ep ))
    {
    case EXCEPTION_CONTINUE_SEARCH:
        return ExceptionContinueSearch;
    case EXCEPTION_CONTINUE_EXECUTION:
        return ExceptionContinueExecution;
    case EXCEPTION_EXECUTE_HANDLER:
        break;
    }
    NtTerminateProcess( GetCurrentProcess(), rec->ExceptionCode );
    return ExceptionContinueExecution;
}


#if defined(__x86_64__) || defined(__arm__) || defined(__aarch64__)

struct dynamic_unwind_entry
{
    struct list       entry;
    ULONG_PTR         base;
    ULONG_PTR         end;
    RUNTIME_FUNCTION *table;
    DWORD             count;
    DWORD             max_count;
    PGET_RUNTIME_FUNCTION_CALLBACK callback;
    PVOID             context;
};

static struct list dynamic_unwind_list = LIST_INIT(dynamic_unwind_list);

static RTL_CRITICAL_SECTION dynamic_unwind_section;
static RTL_CRITICAL_SECTION_DEBUG dynamic_unwind_debug =
{
    0, 0, &dynamic_unwind_section,
    { &dynamic_unwind_debug.ProcessLocksList, &dynamic_unwind_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": dynamic_unwind_section") }
};
static RTL_CRITICAL_SECTION dynamic_unwind_section = { &dynamic_unwind_debug, -1, 0, 0, 0, 0 };

#if defined(__arm64ec__) || defined(__aarch64__)
static ULONG_PTR get_runtime_function_end_arm64( ARM64_RUNTIME_FUNCTION *func, ULONG_PTR addr )
{
    if (func->Flag) return func->BeginAddress + func->FunctionLength * 4;
    else
    {
        struct unwind_info
        {
            DWORD function_length : 18;
            DWORD version : 2;
            DWORD x : 1;
            DWORD e : 1;
            DWORD epilog : 5;
            DWORD codes : 5;
        } *info = (struct unwind_info *)(addr + func->UnwindData);
        return func->BeginAddress + info->function_length * 4;
    }
}
#endif

static ULONG_PTR get_runtime_function_end( RUNTIME_FUNCTION *func, ULONG_PTR addr )
{
#if defined(__x86_64__)
    return func->EndAddress;
#elif defined(__arm__)
    if (func->Flag) return func->BeginAddress + func->FunctionLength * 2;
    else
    {
        struct unwind_info
        {
            DWORD function_length : 18;
            DWORD version : 2;
            DWORD x : 1;
            DWORD e : 1;
            DWORD f : 1;
            DWORD count : 5;
            DWORD words : 4;
        } *info = (struct unwind_info *)(addr + func->UnwindData);
        return func->BeginAddress + info->function_length * 2;
    }
#else
    return get_runtime_function_end_arm64( (ARM64_RUNTIME_FUNCTION *)func, addr );
#endif
}

/**********************************************************************
 *              RtlAddFunctionTable   (NTDLL.@)
 */
BOOLEAN CDECL RtlAddFunctionTable( RUNTIME_FUNCTION *table, DWORD count, ULONG_PTR addr )
{
    struct dynamic_unwind_entry *entry;

    TRACE( "%p %lu %Ix\n", table, count, addr );

    /* NOTE: Windows doesn't check if table is aligned or a NULL pointer */

    entry = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(*entry) );
    if (!entry)
        return FALSE;

    entry->base      = addr;
    /* TODO: test that this adds as an x64 table even to an EC code range */
    entry->end       = addr + (count ? get_runtime_function_end( &table[count - 1], addr ) : 0);
    entry->table     = table;
    entry->count     = count;
    entry->max_count = 0;
    entry->callback  = NULL;
    entry->context   = NULL;

    RtlEnterCriticalSection( &dynamic_unwind_section );
    list_add_tail( &dynamic_unwind_list, &entry->entry );
    RtlLeaveCriticalSection( &dynamic_unwind_section );
    return TRUE;
}


/**********************************************************************
 *              RtlInstallFunctionTableCallback   (NTDLL.@)
 */
BOOLEAN CDECL RtlInstallFunctionTableCallback( ULONG_PTR table, ULONG_PTR base, DWORD length,
                                               PGET_RUNTIME_FUNCTION_CALLBACK callback, PVOID context,
                                               PCWSTR dll )
{
    struct dynamic_unwind_entry *entry;

    TRACE( "%Ix %Ix %ld %p %p %s\n", table, base, length, callback, context, wine_dbgstr_w(dll) );

    /* NOTE: Windows doesn't check if the provided callback is a NULL pointer */

    /* both low-order bits must be set */
    if ((table & 0x3) != 0x3)
        return FALSE;

    entry = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(*entry) );
    if (!entry)
        return FALSE;

    entry->base      = base;
    entry->end       = base + length;
    entry->table     = (RUNTIME_FUNCTION *)table;
    entry->count     = 0;
    entry->max_count = 0;
    entry->callback  = callback;
    entry->context   = context;

    RtlEnterCriticalSection( &dynamic_unwind_section );
    list_add_tail( &dynamic_unwind_list, &entry->entry );
    RtlLeaveCriticalSection( &dynamic_unwind_section );

    return TRUE;
}


/*************************************************************************
 *              RtlAddGrowableFunctionTable   (NTDLL.@)
 */
DWORD WINAPI RtlAddGrowableFunctionTable( void **table, RUNTIME_FUNCTION *functions, DWORD count,
                                          DWORD max_count, ULONG_PTR base, ULONG_PTR end )
{
    struct dynamic_unwind_entry *entry;

    TRACE( "%p, %p, %lu, %lu, %Ix, %Ix\n", table, functions, count, max_count, base, end );

    entry = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(*entry) );
    if (!entry)
        return STATUS_NO_MEMORY;

    entry->base      = base;
    entry->end       = end;
    entry->table     = functions;
    entry->count     = count;
    entry->max_count = max_count;
    entry->callback  = NULL;
    entry->context   = NULL;

    RtlEnterCriticalSection( &dynamic_unwind_section );
    list_add_tail( &dynamic_unwind_list, &entry->entry );
    RtlLeaveCriticalSection( &dynamic_unwind_section );

    *table = entry;

    return STATUS_SUCCESS;
}


/*************************************************************************
 *              RtlGrowFunctionTable   (NTDLL.@)
 */
void WINAPI RtlGrowFunctionTable( void *table, DWORD count )
{
    struct dynamic_unwind_entry *entry;

    TRACE( "%p, %lu\n", table, count );

    RtlEnterCriticalSection( &dynamic_unwind_section );
    LIST_FOR_EACH_ENTRY( entry, &dynamic_unwind_list, struct dynamic_unwind_entry, entry )
    {
        if (entry == table)
        {
            if (count > entry->count && count <= entry->max_count)
                entry->count = count;
            break;
        }
    }
    RtlLeaveCriticalSection( &dynamic_unwind_section );
}


/*************************************************************************
 *              RtlDeleteGrowableFunctionTable   (NTDLL.@)
 */
void WINAPI RtlDeleteGrowableFunctionTable( void *table )
{
    struct dynamic_unwind_entry *entry, *to_free = NULL;

    TRACE( "%p\n", table );

    RtlEnterCriticalSection( &dynamic_unwind_section );
    LIST_FOR_EACH_ENTRY( entry, &dynamic_unwind_list, struct dynamic_unwind_entry, entry )
    {
        if (entry == table)
        {
            to_free = entry;
            list_remove( &entry->entry );
            break;
        }
    }
    RtlLeaveCriticalSection( &dynamic_unwind_section );

    RtlFreeHeap( GetProcessHeap(), 0, to_free );
}


/**********************************************************************
 *              RtlDeleteFunctionTable   (NTDLL.@)
 */
BOOLEAN CDECL RtlDeleteFunctionTable( RUNTIME_FUNCTION *table )
{
    struct dynamic_unwind_entry *entry, *to_free = NULL;

    TRACE( "%p\n", table );

    RtlEnterCriticalSection( &dynamic_unwind_section );
    LIST_FOR_EACH_ENTRY( entry, &dynamic_unwind_list, struct dynamic_unwind_entry, entry )
    {
        if (entry->table == table)
        {
            to_free = entry;
            list_remove( &entry->entry );
            break;
        }
    }
    RtlLeaveCriticalSection( &dynamic_unwind_section );

    if (!to_free) return FALSE;

    RtlFreeHeap( GetProcessHeap(), 0, to_free );
    return TRUE;
}


/* helper for lookup_function_info() */
static RUNTIME_FUNCTION *find_function_info( ULONG_PTR pc, ULONG_PTR base,
                                             RUNTIME_FUNCTION *func, ULONG size )
{
    int min = 0;
    int max = size - 1;

    while (min <= max)
    {
        int pos = (min + max) / 2;
#ifdef __x86_64__
#ifdef __arm64ec__
        if (!RtlIsEcCode( (void *)pc ))
#endif
        {
            if (pc < base + func[pos].BeginAddress) max = pos - 1;
            else if (pc >= base + get_runtime_function_end( &func[pos], base )) min = pos + 1;
            else
            {
                func += pos;
                while (func->UnwindData & 1)  /* follow chained entry */
                    func = (RUNTIME_FUNCTION *)(base + (func->UnwindData & ~1));
                return func;
            }

        }
#ifdef __arm64ec__
        else
#endif
#endif
#if defined(__aarch64__) || defined(__arm64ec__)
        {
            ARM64_RUNTIME_FUNCTION *arm_func = (ARM64_RUNTIME_FUNCTION *)func + pos;
            if (pc < base + arm_func->BeginAddress) max = pos - 1;
            else if (pc >= base + get_runtime_function_end_arm64( arm_func, base ))
                min = pos + 1;
            else return (RUNTIME_FUNCTION *)(arm_func);
        }
#endif
#if defined(__arm__)
        if (pc < base + (func[pos].BeginAddress & ~1)) max = pos - 1;
        else if (pc >= base + get_runtime_function_end( &func[pos], base )) min = pos + 1;
        else return func + pos;
#endif
    }
    return NULL;
}

/**********************************************************************
 *           lookup_function_info
 */
RUNTIME_FUNCTION *lookup_function_info( ULONG_PTR pc, ULONG_PTR *base, LDR_DATA_TABLE_ENTRY **module )
{
    RUNTIME_FUNCTION *func = NULL;
    struct dynamic_unwind_entry *entry;
    ULONG size;

    /* PE module or wine module */
    if (!LdrFindEntryForAddress( (void *)pc, module ))
    {
        *base = (ULONG_PTR)(*module)->DllBase;
#ifdef __arm64ec__
        if (RtlIsEcCode( (void *)pc ))
        {
            const IMAGE_ARM64EC_METADATA *metadata = get_module_arm64ec_metadata( (*module)->DllBase );
            if (metadata && metadata->ExtraRFETable)
            {
                func = (RUNTIME_FUNCTION *)((char *)(*module)->DllBase + metadata->ExtraRFETable);
                size = metadata->ExtraRFETableSize;
                func = find_function_info( pc, (ULONG_PTR)(*module)->DllBase, func,
                                           size/sizeof(ARM64_RUNTIME_FUNCTION) );
            }
        }
        else
#endif
        {
            func = RtlImageDirectoryEntryToData( (*module)->DllBase, TRUE,
                                                 IMAGE_DIRECTORY_ENTRY_EXCEPTION, &size );
            if (func)
            {
                /* lookup in function table */
                func = find_function_info( pc, (ULONG_PTR)(*module)->DllBase, func, size/sizeof(*func) );
            }
        }
    }
    else
    {
        *module = NULL;

        RtlEnterCriticalSection( &dynamic_unwind_section );
        LIST_FOR_EACH_ENTRY( entry, &dynamic_unwind_list, struct dynamic_unwind_entry, entry )
        {
            if (pc >= entry->base && pc < entry->end)
            {
                *base = entry->base;
                /* use callback or lookup in function table */
                if (entry->callback)
                    func = entry->callback( pc, entry->context );
                else
                    func = find_function_info( pc, entry->base, entry->table, entry->count );
                break;
            }
        }
        RtlLeaveCriticalSection( &dynamic_unwind_section );
    }

    return func;
}

/**********************************************************************
 *              RtlLookupFunctionEntry   (NTDLL.@)
 */
PRUNTIME_FUNCTION WINAPI RtlLookupFunctionEntry( ULONG_PTR pc, ULONG_PTR *base,
                                                 UNWIND_HISTORY_TABLE *table )
{
    LDR_DATA_TABLE_ENTRY *module;
    RUNTIME_FUNCTION *func;

    /* FIXME: should use the history table to make things faster */

    if (!(func = lookup_function_info( pc, base, &module )))
    {
        *base = 0;
        WARN( "no exception table found for %Ix\n", pc );
    }
    return func;
}

#endif  /* __x86_64__ || __arm__ || __aarch64__ */


/*************************************************************
 *            _assert
 */
void DECLSPEC_NORETURN __cdecl _assert( const char *str, const char *file, unsigned int line )
{
    ERR( "%s:%u: Assertion failed %s\n", file, line, debugstr_a(str) );
    RtlRaiseStatus( EXCEPTION_WINE_ASSERTION );
}


/*************************************************************
 *            __wine_spec_unimplemented_stub
 *
 * ntdll-specific implementation to avoid depending on kernel functions.
 * Can be removed once ntdll.spec no longer contains stubs.
 */
void __cdecl __wine_spec_unimplemented_stub( const char *module, const char *function )
{
    EXCEPTION_RECORD record;

    record.ExceptionCode    = EXCEPTION_WINE_STUB;
    record.ExceptionFlags   = EH_NONCONTINUABLE;
    record.ExceptionRecord  = NULL;
    record.ExceptionAddress = __wine_spec_unimplemented_stub;
    record.NumberParameters = 2;
    record.ExceptionInformation[0] = (ULONG_PTR)module;
    record.ExceptionInformation[1] = (ULONG_PTR)function;
    for (;;) RtlRaiseException( &record );
}


/*************************************************************
 *            IsBadStringPtrA
 *
 * IsBadStringPtrA replacement for ntdll, to catch exception in debug traces.
 */
BOOL WINAPI IsBadStringPtrA( LPCSTR str, UINT_PTR max )
{
    if (!str) return TRUE;
    __TRY
    {
        volatile const char *p = str;
        while (p != str + max) if (!*p++) break;
    }
    __EXCEPT_PAGE_FAULT
    {
        return TRUE;
    }
    __ENDTRY
    return FALSE;
}

/*************************************************************
 *            IsBadStringPtrW
 *
 * IsBadStringPtrW replacement for ntdll, to catch exception in debug traces.
 */
BOOL WINAPI IsBadStringPtrW( LPCWSTR str, UINT_PTR max )
{
    if (!str) return TRUE;
    __TRY
    {
        volatile const WCHAR *p = str;
        while (p != str + max) if (!*p++) break;
    }
    __EXCEPT_PAGE_FAULT
    {
        return TRUE;
    }
    __ENDTRY
    return FALSE;
}

#ifdef __i386__
__ASM_STDCALL_IMPORT(IsBadStringPtrA,8)
__ASM_STDCALL_IMPORT(IsBadStringPtrW,8)
#else
__ASM_GLOBAL_IMPORT(IsBadStringPtrA)
__ASM_GLOBAL_IMPORT(IsBadStringPtrW)
#endif

/**********************************************************************
 *              RtlGetEnabledExtendedFeatures   (NTDLL.@)
 */
ULONG64 WINAPI RtlGetEnabledExtendedFeatures(ULONG64 feature_mask)
{
    return user_shared_data->XState.EnabledFeatures & feature_mask;
}

struct context_copy_range
{
    ULONG start;
    ULONG flag;
};

static const struct context_copy_range copy_ranges_amd64[] =
{
    {0x38, 0x1}, {0x3a, 0x4}, { 0x42, 0x1}, { 0x48, 0x10}, { 0x78,  0x2}, { 0x98, 0x1},
    {0xa0, 0x2}, {0xf8, 0x1}, {0x100, 0x8}, {0x2a0,    0}, {0x4b0, 0x10}, {0x4d0,   0}
};

static const struct context_copy_range copy_ranges_x86[] =
{
    {  0x4, 0x10}, {0x1c, 0x8}, {0x8c, 0x4}, {0x9c, 0x2}, {0xb4, 0x1}, {0xcc, 0x20}, {0x1ec, 0},
    {0x2cc,    0},
};

static const struct context_parameters
{
    ULONG arch_flag;
    ULONG supported_flags;
    ULONG context_size;    /* sizeof(CONTEXT) */
    ULONG legacy_size;     /* Legacy context size */
    ULONG context_ex_size; /* sizeof(CONTEXT_EX) */
    ULONG alignment;       /* Used when computing size of context. */
    ULONG true_alignment;  /* Used for actual alignment. */
    ULONG flags_offset;
    const struct context_copy_range *copy_ranges;
}
arch_context_parameters[] =
{
    {
        CONTEXT_AMD64,
        0xd8000000 | CONTEXT_AMD64_ALL | CONTEXT_AMD64_XSTATE,
        sizeof(AMD64_CONTEXT),
        sizeof(AMD64_CONTEXT),
        0x20,
        7,
        TYPE_ALIGNMENT(AMD64_CONTEXT) - 1,
        offsetof(AMD64_CONTEXT,ContextFlags),
        copy_ranges_amd64
    },
    {
        CONTEXT_i386,
        0xd8000000 | CONTEXT_I386_ALL | CONTEXT_I386_XSTATE,
        sizeof(I386_CONTEXT),
        offsetof(I386_CONTEXT,ExtendedRegisters),
        0x18,
        3,
        TYPE_ALIGNMENT(I386_CONTEXT) - 1,
        offsetof(I386_CONTEXT,ContextFlags),
        copy_ranges_x86
    },
};

static const struct context_parameters *context_get_parameters( ULONG context_flags )
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(arch_context_parameters); ++i)
    {
        if (context_flags & arch_context_parameters[i].arch_flag)
            return context_flags & ~arch_context_parameters[i].supported_flags ? NULL : &arch_context_parameters[i];
    }
    return NULL;
}


/**********************************************************************
 *              RtlGetExtendedContextLength2    (NTDLL.@)
 */
NTSTATUS WINAPI RtlGetExtendedContextLength2( ULONG context_flags, ULONG *length, ULONG64 compaction_mask )
{
    const struct context_parameters *p;
    ULONG64 supported_mask;
    ULONG64 size;

    TRACE( "context_flags %#lx, length %p, compaction_mask %s.\n", context_flags, length,
            wine_dbgstr_longlong(compaction_mask) );

    if (!(p = context_get_parameters( context_flags )))
        return STATUS_INVALID_PARAMETER;

    if (!(context_flags & 0x40))
    {
        *length = p->context_size + p->context_ex_size + p->alignment;
        return STATUS_SUCCESS;
    }

    if (!(supported_mask = RtlGetEnabledExtendedFeatures( ~(ULONG64)0) ))
        return STATUS_NOT_SUPPORTED;

    compaction_mask &= supported_mask;

    size = p->context_size + p->context_ex_size + offsetof(XSTATE, YmmContext) + 63;

    if (compaction_mask & supported_mask & (1 << XSTATE_AVX))
        size += sizeof(YMMCONTEXT);

    *length = size;
    return STATUS_SUCCESS;
}


/**********************************************************************
 *              RtlGetExtendedContextLength    (NTDLL.@)
 */
NTSTATUS WINAPI RtlGetExtendedContextLength( ULONG context_flags, ULONG *length )
{
    return RtlGetExtendedContextLength2( context_flags, length, ~(ULONG64)0 );
}


/**********************************************************************
 *              RtlInitializeExtendedContext2    (NTDLL.@)
 */
NTSTATUS WINAPI RtlInitializeExtendedContext2( void *context, ULONG context_flags, CONTEXT_EX **context_ex,
        ULONG64 compaction_mask )
{
    const struct context_parameters *p;
    ULONG64 supported_mask = 0;
    CONTEXT_EX *c_ex;

    TRACE( "context %p, context_flags %#lx, context_ex %p, compaction_mask %s.\n",
            context, context_flags, context_ex, wine_dbgstr_longlong(compaction_mask));

    if (!(p = context_get_parameters( context_flags )))
        return STATUS_INVALID_PARAMETER;

    if ((context_flags & 0x40) && !(supported_mask = RtlGetEnabledExtendedFeatures( ~(ULONG64)0 )))
        return STATUS_NOT_SUPPORTED;

    context = (void *)(((ULONG_PTR)context + p->true_alignment) & ~(ULONG_PTR)p->true_alignment);
    *(ULONG *)((BYTE *)context + p->flags_offset) = context_flags;

    *context_ex = c_ex = (CONTEXT_EX *)((BYTE *)context + p->context_size);
    c_ex->Legacy.Offset = c_ex->All.Offset = -(LONG)p->context_size;
    c_ex->Legacy.Length = context_flags & 0x20 ? p->context_size : p->legacy_size;

    if (context_flags & 0x40)
    {
        XSTATE *xs;

        compaction_mask &= supported_mask;

        xs = (XSTATE *)(((ULONG_PTR)c_ex + p->context_ex_size + 63) & ~(ULONG_PTR)63);

        c_ex->XState.Offset = (ULONG_PTR)xs - (ULONG_PTR)c_ex;
        c_ex->XState.Length = offsetof(XSTATE, YmmContext);
        compaction_mask &= supported_mask;

        if (compaction_mask & (1 << XSTATE_AVX))
            c_ex->XState.Length += sizeof(YMMCONTEXT);

        memset( xs, 0, c_ex->XState.Length );
        if (user_shared_data->XState.CompactionEnabled)
            xs->CompactionMask = ((ULONG64)1 << 63) | compaction_mask;

        c_ex->All.Length = p->context_size + c_ex->XState.Offset + c_ex->XState.Length;
    }
    else
    {
        c_ex->XState.Offset = 25; /* According to the tests, it is just 25 if CONTEXT_XSTATE is not specified. */
        c_ex->XState.Length = 0;
        c_ex->All.Length = p->context_size + 24; /* sizeof(CONTEXT_EX) minus 8 alignment bytes on x64. */
    }

    return STATUS_SUCCESS;
}


/**********************************************************************
 *              RtlInitializeExtendedContext    (NTDLL.@)
 */
NTSTATUS WINAPI RtlInitializeExtendedContext( void *context, ULONG context_flags, CONTEXT_EX **context_ex )
{
    return RtlInitializeExtendedContext2( context, context_flags, context_ex, ~(ULONG64)0 );
}


/**********************************************************************
 *              RtlLocateExtendedFeature2    (NTDLL.@)
 */
void * WINAPI RtlLocateExtendedFeature2( CONTEXT_EX *context_ex, ULONG feature_id,
        XSTATE_CONFIGURATION *xstate_config, ULONG *length )
{
    TRACE( "context_ex %p, feature_id %lu, xstate_config %p, length %p.\n",
            context_ex, feature_id, xstate_config, length );

    if (!xstate_config)
    {
        FIXME( "NULL xstate_config.\n" );
        return NULL;
    }

    if (xstate_config != &user_shared_data->XState)
    {
        FIXME( "Custom xstate configuration is not supported.\n" );
        return NULL;
    }

    if (feature_id != XSTATE_AVX)
        return NULL;

    if (length)
        *length = sizeof(YMMCONTEXT);

    if (context_ex->XState.Length < sizeof(XSTATE))
        return NULL;

    return (BYTE *)context_ex + context_ex->XState.Offset + offsetof(XSTATE, YmmContext);
}


/**********************************************************************
 *              RtlLocateExtendedFeature    (NTDLL.@)
 */
void * WINAPI RtlLocateExtendedFeature( CONTEXT_EX *context_ex, ULONG feature_id,
        ULONG *length )
{
    return RtlLocateExtendedFeature2( context_ex, feature_id, &user_shared_data->XState, length );
}

/**********************************************************************
 *              RtlLocateLegacyContext      (NTDLL.@)
 */
void * WINAPI RtlLocateLegacyContext( CONTEXT_EX *context_ex, ULONG *length )
{
    if (length)
        *length = context_ex->Legacy.Length;

    return (BYTE *)context_ex + context_ex->Legacy.Offset;
}

/**********************************************************************
 *              RtlSetExtendedFeaturesMask  (NTDLL.@)
 */
void WINAPI RtlSetExtendedFeaturesMask( CONTEXT_EX *context_ex, ULONG64 feature_mask )
{
    XSTATE *xs = (XSTATE *)((BYTE *)context_ex + context_ex->XState.Offset);

    xs->Mask = RtlGetEnabledExtendedFeatures( feature_mask ) & ~(ULONG64)3;
}


/**********************************************************************
 *              RtlGetExtendedFeaturesMask  (NTDLL.@)
 */
ULONG64 WINAPI RtlGetExtendedFeaturesMask( CONTEXT_EX *context_ex )
{
    XSTATE *xs = (XSTATE *)((BYTE *)context_ex + context_ex->XState.Offset);

    return xs->Mask & ~(ULONG64)3;
}


static void context_copy_ranges( BYTE *d, DWORD context_flags, BYTE *s, const struct context_parameters *p )
{
    const struct context_copy_range *range;
    unsigned int start;

    *((ULONG *)(d + p->flags_offset)) |= context_flags;

    start = 0;
    range = p->copy_ranges;
    do
    {
        if (range->flag & context_flags)
        {
            if (!start)
                start = range->start;
        }
        else if (start)
        {
            memcpy( d + start, s + start, range->start - start );
            start = 0;
        }
    }
    while (range++->start != p->context_size);
}


/***********************************************************************
 *              RtlCopyContext  (NTDLL.@)
 */
NTSTATUS WINAPI RtlCopyContext( CONTEXT *dst, DWORD context_flags, CONTEXT *src )
{
    DWORD context_size, arch_flag, flags_offset, dst_flags, src_flags;
    static const DWORD arch_mask = CONTEXT_i386 | CONTEXT_AMD64;
    const struct context_parameters *p;
    BYTE *d, *s;

    TRACE("dst %p, context_flags %#lx, src %p.\n", dst, context_flags, src);

    if (context_flags & 0x40 && !RtlGetEnabledExtendedFeatures( ~(ULONG64)0 )) return STATUS_NOT_SUPPORTED;

    arch_flag = context_flags & arch_mask;
    switch (arch_flag)
    {
    case CONTEXT_i386:
        context_size = sizeof( I386_CONTEXT );
        flags_offset = offsetof( I386_CONTEXT, ContextFlags );
        break;
    case CONTEXT_AMD64:
        context_size = sizeof( AMD64_CONTEXT );
        flags_offset = offsetof( AMD64_CONTEXT, ContextFlags );
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    d = (BYTE *)dst;
    s = (BYTE *)src;
    dst_flags = *(DWORD *)(d + flags_offset);
    src_flags = *(DWORD *)(s + flags_offset);

    if ((dst_flags & arch_mask) != arch_flag || (src_flags & arch_mask) != arch_flag)
        return STATUS_INVALID_PARAMETER;

    context_flags &= src_flags;
    if (context_flags & ~dst_flags & 0x40) return STATUS_BUFFER_OVERFLOW;

    if (context_flags & 0x40)
        return RtlCopyExtendedContext( (CONTEXT_EX *)(d + context_size), context_flags,
                                       (CONTEXT_EX *)(s + context_size) );

    if (!(p = context_get_parameters( context_flags )))
        return STATUS_INVALID_PARAMETER;

    context_copy_ranges( d, context_flags, s, p );
    return STATUS_SUCCESS;
}


/**********************************************************************
 *              RtlCopyExtendedContext      (NTDLL.@)
 */
NTSTATUS WINAPI RtlCopyExtendedContext( CONTEXT_EX *dst, ULONG context_flags, CONTEXT_EX *src )
{
    const struct context_parameters *p;
    XSTATE *dst_xs, *src_xs;
    ULONG64 feature_mask;

    TRACE( "dst %p, context_flags %#lx, src %p.\n", dst, context_flags, src );

    if (!(p = context_get_parameters( context_flags )))
        return STATUS_INVALID_PARAMETER;

    if (!(feature_mask = RtlGetEnabledExtendedFeatures( ~(ULONG64)0 )) && context_flags & 0x40)
        return STATUS_NOT_SUPPORTED;

    context_copy_ranges( RtlLocateLegacyContext( dst, NULL ), context_flags, RtlLocateLegacyContext( src, NULL ), p );

    if (!(context_flags & 0x40))
        return STATUS_SUCCESS;

    if (dst->XState.Length < offsetof(XSTATE, YmmContext))
        return STATUS_BUFFER_OVERFLOW;

    dst_xs = (XSTATE *)((BYTE *)dst + dst->XState.Offset);
    src_xs = (XSTATE *)((BYTE *)src + src->XState.Offset);

    memset(dst_xs, 0, offsetof(XSTATE, YmmContext));
    dst_xs->Mask = (src_xs->Mask & ~(ULONG64)3) & feature_mask;
    dst_xs->CompactionMask = user_shared_data->XState.CompactionEnabled
            ? ((ULONG64)1 << 63) | (src_xs->CompactionMask & feature_mask) : 0;

    if (dst_xs->Mask & 4 && src->XState.Length >= sizeof(XSTATE) && dst->XState.Length >= sizeof(XSTATE))
        memcpy( &dst_xs->YmmContext, &src_xs->YmmContext, sizeof(dst_xs->YmmContext) );
    return STATUS_SUCCESS;
}

#if defined(__x86_64__) || defined(__arm__) || defined(__aarch64__)

#if defined(__aarch64__)
#define INSTR_SIZE 4
#elif defined(__arm__)
#define INSTR_SIZE 2
#endif

#ifdef __x86_64__
#define CTX_REG_PC(context) (context)->Rip
#define CTX_REG_SP(context) (context)->Rsp
#define CTX_REG_RETVAL(context) (context)->Rax
#define DISPATCHER_TARGET(dispatch) (dispatch)->TargetIp
#define IS_X86_64_CODE(arg) TRUE

#else

#define IS_ARM_CODE(arg) TRUE
#define DISPATCHER_TARGET(dispatch) (dispatch)->TargetPc
#define CTX_REG_PC(context) (context)->Pc
#define CTX_REG_LR(context) (context)->Lr
#define CTX_REG_SP(context) (context)->Sp

#if defined(__aarch64__)
#define CTX_REG_RETVAL(context) (context)->X0
#else
#define CTX_REG_RETVAL(context) (context)->R0
#endif

#endif

typedef struct _SCOPE_TABLE
{
    ULONG Count;
    struct
    {
        ULONG BeginAddress;
        ULONG EndAddress;
        ULONG HandlerAddress;
        ULONG JumpTarget;
    } ScopeRecord[1];
} SCOPE_TABLE, *PSCOPE_TABLE;

static void dump_scope_table( ULONG_PTR base, const SCOPE_TABLE *table )
{
    unsigned int i;

    TRACE( "scope table at %p\n", table );
    for (i = 0; i < table->Count; i++)
        TRACE( "  %u: %p-%p handler %p target %p\n", i,
               (char *)base + table->ScopeRecord[i].BeginAddress,
               (char *)base + table->ScopeRecord[i].EndAddress,
               (char *)base + table->ScopeRecord[i].HandlerAddress,
               (char *)base + table->ScopeRecord[i].JumpTarget );
}

/*******************************************************************
 *         is_valid_frame
 */
static inline BOOL is_valid_frame( ULONG_PTR frame )
{
#ifdef __arm__
    if (frame & 3) return FALSE;
#else
    if (frame & 7) return FALSE;
#endif
    return ((void *)frame >= NtCurrentTeb()->Tib.StackLimit &&
            (void *)frame <= NtCurrentTeb()->Tib.StackBase);
}

/***********************************************************************
 *           virtual_unwind
 */
static NTSTATUS virtual_unwind( ULONG type, DISPATCHER_CONTEXT *dispatch, CONTEXT *context )
{
    LDR_DATA_TABLE_ENTRY *module;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR pc = CTX_REG_PC(context);

    dispatch->ImageBase = 0;
    dispatch->ScopeIndex = 0;
    dispatch->EstablisherFrame = 0;
    dispatch->ControlPc = CTX_REG_PC(context);

#if defined(__aarch64__) || defined(__arm__)
    /*
     * TODO: CONTEXT_UNWOUND_TO_CALL should be cleared if unwound past a
     * signal frame.
     */
    if ((context->ContextFlags & CONTEXT_UNWOUND_TO_CALL) && IS_ARM_CODE( (const void *)pc ))
    {
        dispatch->ControlPcIsUnwound = TRUE;
        pc -= INSTR_SIZE;
    }
#endif

    /* first look for PE exception information */

    if ((dispatch->FunctionEntry = lookup_function_info( pc, &dispatch->ImageBase, &module )))
    {
        dispatch->LanguageHandler = RtlVirtualUnwind( type, dispatch->ImageBase, pc,
                                                      dispatch->FunctionEntry, context,
                                                      &dispatch->HandlerData, &dispatch->EstablisherFrame,
                                                      NULL );
        return status;
    }

    /* then look for host system exception information */

    if (!module || (module->Flags & LDR_WINE_INTERNAL))
    {
        struct unwind_builtin_dll_params params = { type, dispatch, context };

        status = WINE_UNIX_CALL( unix_unwind_builtin_dll, &params );
        if (!status)
        {
            dispatch->FunctionEntry = NULL;
            if (dispatch->LanguageHandler && !module)
            {
                FIXME( "calling personality routine in system library not supported yet\n" );
                dispatch->LanguageHandler = NULL;
            }
        }
        if (status != STATUS_UNSUCCESSFUL) return status;
    }

    dispatch->EstablisherFrame = CTX_REG_SP(context);
    dispatch->LanguageHandler = NULL;

#if defined(__aarch64__) || defined(__arm__)
    if (IS_ARM_CODE( (const void *) pc ))
    {
        status = CTX_REG_PC(context) != CTX_REG_LR(context) ?
                 STATUS_SUCCESS : STATUS_INVALID_DISPOSITION;

        CTX_REG_PC(context) = CTX_REG_LR(context);
        context->ContextFlags |= CONTEXT_UNWOUND_TO_CALL;
#ifdef __aarch64__
        if (status == STATUS_SUCCESS)
            dispatch->EstablisherFrame = CTX_REG_FP(context);
#endif
    }
#endif

#if defined(__x86_64__)
    if (IS_X86_64_CODE( (const void *) pc ))
    {
        status = STATUS_SUCCESS;

        dispatch->LanguageHandler = NULL;
        context->Rip = *(ULONG64 *)context->Rsp;
        context->Rsp = context->Rsp + sizeof(ULONG64);
    }
#endif

    WARN( "no info found for %p, %s\n", (void *) pc, status == STATUS_SUCCESS ?
          "assuming leaf function" : "error, stuck" );

    return status;
}

#ifdef __aarch64__
static void fill_nonvolatile_regs( DISPATCHER_CONTEXT_NONVOLREG_ARM64 *regs,
                                   CONTEXT *context )
{
    int i;
    for (i = 0; i < NONVOL_INT_NUMREG_ARM64; i++) regs->GpNvRegs[i] = ec_context->X[i+19];
    for (i = 0; i < NONVOL_FP_NUMREG_ARM64; i++) regs->FpNvRegs[i] = ec_context->V[i + 8].D[0];
}
#endif
//TODO: arm??

DWORD __cdecl nested_exception_handler( EXCEPTION_RECORD *rec, EXCEPTION_REGISTRATION_RECORD *frame,
                                        CONTEXT *context, EXCEPTION_REGISTRATION_RECORD **dispatcher )
{
    if (!(rec->ExceptionFlags & (EH_UNWINDING | EH_EXIT_UNWIND)))
        return ExceptionNestedException;

    return ExceptionContinueSearch;
}

/***********************************************************************
 *                exception_handler_call_wrapper
 */
#if defined(__WINE_PE_BUILD) && defined(__x86_64__) // TODO: impl for all, maybe move to signal_*?
DWORD WINAPI exception_handler_call_wrapper( EXCEPTION_RECORD *rec, void *frame,
                                      CONTEXT *context, DISPATCHER_CONTEXT *dispatch );

C_ASSERT( offsetof(DISPATCHER_CONTEXT, LanguageHandler) == 0x30 );

__ASM_GLOBAL_FUNC( exception_handler_call_wrapper,
                   ".seh_endprologue\n\t"
                   "subq $0x28, %rsp\n\t"
                   ".seh_stackalloc 0x28\n\t"
                   "callq *0x30(%r9)\n\t"       /* dispatch->LanguageHandler */
                   "nop\n\t"                    /* avoid epilogue so handler is called */
                   "addq $0x28, %rsp\n\t"
                   "ret\n\t"
                   ".seh_handler " __ASM_NAME("nested_exception_handler") ", @except\n\t" )
#else
static DWORD exception_handler_call_wrapper( EXCEPTION_RECORD *rec, void *frame,
                                             CONTEXT *context, DISPATCHER_CONTEXT *dispatch )
{
    EXCEPTION_REGISTRATION_RECORD wrapper_frame;
    DWORD res;

    wrapper_frame.Handler = nested_exception_handler;
    __wine_push_frame( &wrapper_frame );
    res = dispatch->LanguageHandler( rec, (void *)dispatch->EstablisherFrame, context, (DISPATCHER_CONTEXT *)dispatch );
    __wine_pop_frame( &wrapper_frame );
    return res;
}
#endif

/**********************************************************************
 *           call_handler
 *
 * Call a single exception handler.
 */
static DWORD call_handler( EXCEPTION_RECORD *rec, CONTEXT *context, DISPATCHER_CONTEXT *dispatch )
{
    DWORD res;

    TRACE_(seh)( "calling handler %p (rec=%p, frame=%p context=%p, dispatch=%p)\n",
                 dispatch->LanguageHandler, rec, (void *)dispatch->EstablisherFrame, dispatch->ContextRecord, dispatch );
    res = exception_handler_call_wrapper( rec, (void *)dispatch->EstablisherFrame, context, dispatch );
    TRACE_(seh)( "handler at %p returned %lu\n", dispatch->LanguageHandler, res );

    rec->ExceptionFlags &= EH_NONCONTINUABLE;
    return res;
}


/**********************************************************************
 *           call_teb_handler
 *
 * Call a single exception handler from the TEB chain.
 * FIXME: Handle nested exceptions.
 */
static DWORD call_teb_handler( EXCEPTION_RECORD *rec, CONTEXT *context, DISPATCHER_CONTEXT *dispatch,
                                  EXCEPTION_REGISTRATION_RECORD *teb_frame )
{
    DWORD res;

    TRACE_(seh)( "calling TEB handler %p (rec=%p, frame=%p context=%p, dispatch=%p)\n",
                 teb_frame->Handler, rec, teb_frame, dispatch->ContextRecord, dispatch );
    res = teb_frame->Handler( rec, teb_frame, context, (EXCEPTION_REGISTRATION_RECORD**)dispatch );
    TRACE_(seh)( "handler at %p returned %lu\n", teb_frame->Handler, res );
    return res;
}


/**********************************************************************
 *           call_stack_handlers
 *
 * Call the stack handlers chain.
 */
NTSTATUS call_stack_handlers( EXCEPTION_RECORD *rec, CONTEXT *orig_context )
{
    EXCEPTION_REGISTRATION_RECORD *teb_frame = NtCurrentTeb()->Tib.ExceptionList;
    UNWIND_HISTORY_TABLE table;
#if defined(__aarch64__) || defined(__arm__)
    // Obviously not right for arm32...
    DISPATCHER_CONTEXT_NONVOLREG_ARM64 nonvolatile_regs;
#endif
    DISPATCHER_CONTEXT dispatch;
    CONTEXT context;
    NTSTATUS status;

    context = *orig_context;
#ifdef __x86_64__
    context.ContextFlags &= ~0x40; /* Clear xstate flag. */
#endif

    DISPATCHER_TARGET(&dispatch) = 0;
    dispatch.ContextRecord       = &context;
    dispatch.HistoryTable        = &table;
#if defined(__aarch64__) || defined(__arm__)
    fill_nonvolatile_regs( &nonvolatile_regs, &context );
    dispatch.NonVolatileRegisters = nonvolatile_regs.Buffer;
#endif

    for (;;)
    {
        status = virtual_unwind( UNW_FLAG_EHANDLER, &dispatch, &context );
        if (status != STATUS_SUCCESS) return status;

    unwind_done:
        if (!dispatch.EstablisherFrame) break;

        if (!is_valid_frame( dispatch.EstablisherFrame ))
        {
            ERR_(seh)( "invalid frame %p (%p-%p)\n", (void *)dispatch.EstablisherFrame,
                       NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
            rec->ExceptionFlags |= EH_STACK_INVALID;
            break;
        }

        if (dispatch.LanguageHandler)
        {
            switch (call_handler( rec, orig_context, &dispatch ))
            {
            case ExceptionContinueExecution:
                if (rec->ExceptionFlags & EH_NONCONTINUABLE) return STATUS_NONCONTINUABLE_EXCEPTION;
                return STATUS_SUCCESS;
            case ExceptionContinueSearch:
                break;
            case ExceptionNestedException:
                // TODO: not present on arm??
                rec->ExceptionFlags |= EH_NESTED_CALL;
                TRACE_(seh)( "nested exception\n" );
                break;
            case ExceptionCollidedUnwind: {
                ULONG_PTR frame;

                context = *dispatch.ContextRecord;
                dispatch.ContextRecord = &context;
#if defined(__aarch64__) || defined(__arm__)
                fill_nonvolatile_regs( &nonvolatile_regs, &context );
#endif
                RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase,
                        dispatch.ControlPc, dispatch.FunctionEntry,
                        &context, NULL, &frame, NULL ); // TODO: handler data not passed on x86?
                goto unwind_done;
            }
            default:
                return STATUS_INVALID_DISPOSITION;
            }
        }
        /* hack: call wine handlers registered in the tib list */
        else while ((ULONG_PTR)teb_frame < CTX_REG_SP(&context))
        {
            TRACE_(seh)( "found wine frame %p sp %p handler %p\n",
                         teb_frame, (void *)CTX_REG_SP(&context), teb_frame->Handler );
            dispatch.EstablisherFrame = (ULONG_PTR)teb_frame;
            switch (call_teb_handler( rec, orig_context, &dispatch, teb_frame ))
            {
            case ExceptionContinueExecution:
                if (rec->ExceptionFlags & EH_NONCONTINUABLE) return STATUS_NONCONTINUABLE_EXCEPTION;
                return STATUS_SUCCESS;
            case ExceptionContinueSearch:
                break;
            case ExceptionNestedException:
                rec->ExceptionFlags |= EH_NESTED_CALL;
                TRACE_(seh)( "nested exception\n" );
                break;
            case ExceptionCollidedUnwind: {
                ULONG_PTR frame;

                context = *dispatch.ContextRecord;
                dispatch.ContextRecord = &context;
#if defined(__aarch64__) || defined(__arm__)
                fill_nonvolatile_regs( &nonvolatile_regs, &context );
#endif
                RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase,
                        dispatch.ControlPc, dispatch.FunctionEntry,
                        &context, NULL, &frame, NULL );
                teb_frame = teb_frame->Prev;
                goto unwind_done;
            }
            default:
                return STATUS_INVALID_DISPOSITION;
            }
            teb_frame = teb_frame->Prev;
        }

        if (CTX_REG_SP(&context) == (ULONG_PTR)NtCurrentTeb()->Tib.StackBase) break;
#if defined(__aarch64__) || defined(__arm__)
        fill_nonvolatile_regs( &nonvolatile_regs, &context );
#endif
    }
    return STATUS_UNHANDLED_EXCEPTION;
}

struct unwind_exception_frame
{
    EXCEPTION_REGISTRATION_RECORD frame;
#ifdef __x86_64__
    char dummy[0x10]; /* Layout 'dispatch' accessed from unwind_exception_handler() so it is above register
                       * save space when .seh handler is used. */
#endif
    DISPATCHER_CONTEXT *dispatch;
};

/**********************************************************************
 *           unwind_exception_handler
 *
 * Handler for exceptions happening while calling an unwind handler.
 */
DWORD __cdecl unwind_exception_handler( EXCEPTION_RECORD *rec, EXCEPTION_REGISTRATION_RECORD *frame,
                                        CONTEXT *context, EXCEPTION_REGISTRATION_RECORD **dispatcher )
{
    struct unwind_exception_frame *unwind_frame = (struct unwind_exception_frame *)frame;
    DISPATCHER_CONTEXT *dispatch = (DISPATCHER_CONTEXT *)dispatcher;

    /* copy the original dispatcher into the current one, except for the TargetIp */
    dispatch->ControlPc        = unwind_frame->dispatch->ControlPc;
    dispatch->ImageBase        = unwind_frame->dispatch->ImageBase;
    dispatch->FunctionEntry    = unwind_frame->dispatch->FunctionEntry;
    dispatch->EstablisherFrame = unwind_frame->dispatch->EstablisherFrame;
    dispatch->ContextRecord    = unwind_frame->dispatch->ContextRecord;
    dispatch->LanguageHandler  = unwind_frame->dispatch->LanguageHandler;
    dispatch->HandlerData      = unwind_frame->dispatch->HandlerData;
    dispatch->HistoryTable     = unwind_frame->dispatch->HistoryTable;
    dispatch->ScopeIndex       = unwind_frame->dispatch->ScopeIndex;
    TRACE( "detected collided unwind\n" );
    return ExceptionCollidedUnwind;
}

/***********************************************************************
 *                unwind_handler_call_wrapper
 */
#if defined(__WINE_PE_BUILD) && defined(__x86_64__) // TODO: impl for all, maybe move to signal_*?
DWORD WINAPI unwind_handler_call_wrapper( EXCEPTION_RECORD *rec, void *frame,
                                   CONTEXT *context, DISPATCHER_CONTEXT *dispatch );

C_ASSERT( sizeof(struct unwind_exception_frame) == 0x28 );
C_ASSERT( offsetof(struct unwind_exception_frame, dispatch) == 0x20 );
C_ASSERT( offsetof(DISPATCHER_CONTEXT, LanguageHandler) == 0x30 );

__ASM_GLOBAL_FUNC( unwind_handler_call_wrapper,
                   ".seh_endprologue\n\t"
                   "subq $0x28,%rsp\n\t"
                   ".seh_stackalloc 0x28\n\t"
                   "movq %r9,0x20(%rsp)\n\t"   /* unwind_exception_frame->dispatch */
                   "callq *0x30(%r9)\n\t"      /* dispatch->LanguageHandler */
                   "nop\n\t"                   /* avoid epilogue so handler is called */
                   "addq $0x28, %rsp\n\t"
                   "ret\n\t"
                   ".seh_handler " __ASM_NAME("unwind_exception_handler") ", @except, @unwind\n\t" )
#else
static DWORD unwind_handler_call_wrapper( EXCEPTION_RECORD *rec, void *frame,
                                          CONTEXT *context, DISPATCHER_CONTEXT *dispatch )
{
    struct unwind_exception_frame wrapper_frame;
    DWORD res;

    wrapper_frame.frame.Handler = unwind_exception_handler;
    wrapper_frame.dispatch = dispatch;
    __wine_push_frame( &wrapper_frame.frame );
    res = dispatch->LanguageHandler( rec, (void *)dispatch->EstablisherFrame, dispatch->ContextRecord,
                                     (DISPATCHER_CONTEXT *) dispatch );
    __wine_pop_frame( &wrapper_frame.frame );
    return res;
}
#endif

/**********************************************************************
 *           call_unwind_handler
 *
 * Call a single unwind handler.
 */
DWORD call_unwind_handler( EXCEPTION_RECORD *rec, DISPATCHER_CONTEXT *dispatch )
{
    DWORD res;

    TRACE( "calling handler %p (rec=%p, frame=%p context=%p, dispatch=%p)\n",
           dispatch->LanguageHandler, rec, (void *)dispatch->EstablisherFrame, dispatch->ContextRecord, dispatch );
    res = unwind_handler_call_wrapper( rec, (void *)dispatch->EstablisherFrame, dispatch->ContextRecord, dispatch );
    TRACE( "handler %p returned %lx\n", dispatch->LanguageHandler, res );

    switch (res)
    {
    case ExceptionContinueSearch:
    case ExceptionCollidedUnwind:
        break;
    default:
        raise_status( STATUS_INVALID_DISPOSITION, rec );
        break;
    }

    return res;
}


/**********************************************************************
 *           call_teb_unwind_handler
 *
 * Call a single unwind handler from the TEB chain.
 */
static DWORD call_teb_unwind_handler( EXCEPTION_RECORD *rec, DISPATCHER_CONTEXT *dispatch,
                                      EXCEPTION_REGISTRATION_RECORD *teb_frame )
{
    DWORD res;

    TRACE( "calling TEB handler %p (rec=%p, frame=%p context=%p, dispatch=%p)\n",
           teb_frame->Handler, rec, teb_frame, dispatch->ContextRecord, dispatch );
    res = teb_frame->Handler( rec, teb_frame, dispatch->ContextRecord, (EXCEPTION_REGISTRATION_RECORD**)dispatch );
    TRACE( "handler at %p returned %lu\n", teb_frame->Handler, res );

    switch (res)
    {
    case ExceptionContinueSearch:
    case ExceptionCollidedUnwind:
        break;
    default:
        raise_status( STATUS_INVALID_DISPOSITION, rec );
        break;
    }

    return res;
}

/*******************************************************************
 *              RtlRestoreContext (NTDLL.@)
 */
void CDECL RtlRestoreContext( CONTEXT *context, EXCEPTION_RECORD *rec )
{
    EXCEPTION_REGISTRATION_RECORD *teb_frame = NtCurrentTeb()->Tib.ExceptionList;

    if (rec && rec->ExceptionCode == STATUS_LONGJUMP && rec->NumberParameters >= 1)
    {
        context_restore_from_jmpbuf( context, (void *)rec->ExceptionInformation[0] );
    }
    else if (rec && rec->ExceptionCode == STATUS_UNWIND_CONSOLIDATE && rec->NumberParameters >= 1)
    {
        PVOID (CALLBACK *consolidate)(EXCEPTION_RECORD *) = (void *)rec->ExceptionInformation[0];
#ifdef __aarch64__
        rec->ExceptionInformation[10] = (ULONG_PTR)&context->X19;
#elif defined(__arm__)
        rec->ExceptionInformation[10] = (ULONG_PTR)&context->R4;
#endif
        // TODO: check if this is populated on a64ec
        TRACE_(seh)( "calling consolidate callback %p (rec=%p)\n", consolidate, rec );
        CTX_REG_PC(context) = (ULONG_PTR)call_consolidate_callback( context, consolidate, rec );
    }

    /* hack: remove no longer accessible TEB frames */
    while ((ULONG_PTR)teb_frame < CTX_REG_SP(context))
    {
        TRACE_(seh)( "removing TEB frame: %p\n", teb_frame );
        teb_frame = __wine_pop_frame( teb_frame );
    }

    TRACE_(seh)( "returning to %p stack %p\n", (void *)CTX_REG_PC(context), (void *)CTX_REG_SP(context) );
    NtContinue( context, FALSE );
}

/*******************************************************************
 *                RtlUnwindEx (NTDLL.@)
 */
void WINAPI RtlUnwindEx( PVOID end_frame, PVOID target_ip, EXCEPTION_RECORD *rec,
                         PVOID retval, CONTEXT *context, UNWIND_HISTORY_TABLE *table )
{
    EXCEPTION_REGISTRATION_RECORD *teb_frame = NtCurrentTeb()->Tib.ExceptionList;
    EXCEPTION_RECORD record;
#if defined(__aarch64__) || defined(__arm__)
    // Obviously not right for arm32...
    DISPATCHER_CONTEXT_NONVOLREG_ARM64 nonvolatile_regs;
#endif
    DISPATCHER_CONTEXT dispatch;

    CONTEXT new_context;
    NTSTATUS status;
    DWORD i;

    RtlCaptureContext( context );
    new_context = *context;

    /* build an exception record, if we do not have one */
    if (!rec)
    {
        record.ExceptionCode    = STATUS_UNWIND;
        record.ExceptionFlags   = 0;
        record.ExceptionRecord  = NULL;
        record.ExceptionAddress = (void *)CTX_REG_PC(context);
        record.NumberParameters = 0;
        rec = &record;
    }

    rec->ExceptionFlags |= EH_UNWINDING | (end_frame ? 0 : EH_EXIT_UNWIND);

    TRACE( "code=%lx flags=%lx end_frame=%p target_ip=%p rip=%p\n",
           rec->ExceptionCode, rec->ExceptionFlags, end_frame, target_ip, (void *)CTX_REG_PC(context) );
    for (i = 0; i < min( EXCEPTION_MAXIMUM_PARAMETERS, rec->NumberParameters ); i++)
        TRACE( " info[%ld]=%p\n", i, (void*)rec->ExceptionInformation[i] );

    context_trace_gprs( context );

    DISPATCHER_TARGET(&dispatch) = (ULONG_PTR)target_ip;
    dispatch.ContextRecord       = context;
    dispatch.HistoryTable        = table;
#if defined(__aarch64__) || defined(__arm__)
    fill_nonvolatile_regs( &nonvolatile_regs, context );
    dispatch.NonVolatileRegisters = nonvolatile_regs.Buffer;
#endif

    for (;;)
    {
        status = virtual_unwind( UNW_FLAG_UHANDLER, &dispatch, &new_context );
        if (status != STATUS_SUCCESS) raise_status( status, rec );

    unwind_done:
        if (!dispatch.EstablisherFrame) break;

        if (!is_valid_frame( dispatch.EstablisherFrame ))
        {
            ERR( "invalid frame %p (%p-%p)\n", (void *)dispatch.EstablisherFrame,
                 NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
            rec->ExceptionFlags |= EH_STACK_INVALID;
            break;
        }

        if (dispatch.LanguageHandler)
        {
            if (end_frame && (dispatch.EstablisherFrame > (ULONG_PTR)end_frame))
            {
                ERR( "invalid end frame %p/%p\n", (void *)dispatch.EstablisherFrame, end_frame );
                raise_status( STATUS_INVALID_UNWIND_TARGET, rec );
            }
            if (dispatch.EstablisherFrame == (ULONG_PTR)end_frame) rec->ExceptionFlags |= EH_TARGET_UNWIND;
            if (call_unwind_handler( rec, &dispatch ) == ExceptionCollidedUnwind)
            {
                ULONG_PTR frame;

                new_context = *dispatch.ContextRecord;
#ifdef __x86_64__
                new_context.ContextFlags &= ~0x40;
#endif
                *context = new_context;
#if defined(__aarch64__) || defined(__arm__)
                fill_nonvolatile_regs( &nonvolatile_regs, context );
#endif
                dispatch.ContextRecord = context;
                RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase,
                        dispatch.ControlPc, dispatch.FunctionEntry,
                        &new_context, NULL, &frame, NULL ); // TODO: handler data not passed on x86?
                rec->ExceptionFlags |= EH_COLLIDED_UNWIND;
                goto unwind_done;
            }
            rec->ExceptionFlags &= ~EH_COLLIDED_UNWIND;
        }
        else  /* hack: call builtin handlers registered in the tib list */
        {
            ULONG_PTR backup_frame = dispatch.EstablisherFrame;
            while ((ULONG_PTR)teb_frame < CTX_REG_SP(&new_context) && (ULONG_PTR)teb_frame < (ULONG_PTR)end_frame)
            {
                TRACE( "found builtin frame %p handler %p\n", teb_frame, teb_frame->Handler );
                dispatch.EstablisherFrame = (ULONG_PTR)teb_frame;
                if (call_teb_unwind_handler( rec, &dispatch, teb_frame ) == ExceptionCollidedUnwind)
                {
                    ULONG_PTR frame;

                    teb_frame = __wine_pop_frame( teb_frame );

                    new_context = *dispatch.ContextRecord;
#ifdef __x86_64__
                    new_context.ContextFlags &= ~0x40;
#endif
                    *context = new_context;
#if defined(__aarch64__) || defined(__arm__)
                    fill_nonvolatile_regs( &nonvolatile_regs, context );
#endif
                    dispatch.ContextRecord = context;
                    RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase,
                            dispatch.ControlPc, dispatch.FunctionEntry,
                            &new_context, NULL, &frame, NULL );
                    rec->ExceptionFlags |= EH_COLLIDED_UNWIND;
                    goto unwind_done;
                }
                teb_frame = __wine_pop_frame( teb_frame );
            }
            if ((ULONG_PTR)teb_frame == (ULONG_PTR)end_frame && (ULONG_PTR)end_frame < CTX_REG_SP(&new_context)) break;
            dispatch.EstablisherFrame = backup_frame;
        }

        if (dispatch.EstablisherFrame == (ULONG_PTR)end_frame) break;
        *context = new_context;
#if defined(__aarch64__) || defined(__arm__)
        fill_nonvolatile_regs( &nonvolatile_regs, context );
#endif
    }

    CTX_REG_RETVAL(context) = (ULONG_PTR)retval;
    CTX_REG_PC(context) = (ULONG_PTR)target_ip;
    RtlRestoreContext(context, rec);
}

/*******************************************************************
 *                RtlUnwind (NTDLL.@)
 */
void WINAPI RtlUnwind( void *frame, void *target_ip, EXCEPTION_RECORD *rec, void *retval )
{
    CONTEXT context;
    RtlUnwindEx( frame, target_ip, rec, retval, &context, NULL );
}

#if defined(__x86_64__) || defined(__aarch64__)
/*******************************************************************
 *                _local_unwind (NTDLL.@)
 */
void WINAPI _local_unwind( void *frame, void *target_ip )
{
    CONTEXT context;
    RtlUnwindEx( frame, target_ip, NULL, NULL, &context, NULL );
}
#else
/*******************************************************************
 *                _jump_unwind (NTDLL.@)
 */
void WINAPI __jump_unwind( void *frame, void *target_ip )
{
    CONTEXT context;
    RtlUnwindEx( frame, target_ip, NULL, NULL, &context, NULL );
}
#endif

/*******************************************************************
 *                __C_specific_handler (NTDLL.@)
 */
EXCEPTION_DISPOSITION WINAPI __C_specific_handler( EXCEPTION_RECORD *rec,
                                                   void *frame,
                                                   CONTEXT *context,
                                                   struct _DISPATCHER_CONTEXT *dispatch )
{
    SCOPE_TABLE *table = dispatch->HandlerData;
    ULONG i;
    ULONG_PTR ControlPc = dispatch->ControlPc;

    TRACE( "%p %p %p %p\n", rec, frame, context, dispatch );
    if (TRACE_ON(seh)) dump_scope_table( dispatch->ImageBase, table );

#if defined(__aarch64__) || defined(__arm__)
    if (IS_ARM_CODE( (const void *)ControlPc ) && ((DISPATCHER_CONTEXT_NATIVE *)dispatch)->ControlPcIsUnwound)
        ControlPc -= INSTR_SIZE;
#endif

    if (rec->ExceptionFlags & (EH_UNWINDING | EH_EXIT_UNWIND))
    {
        for (i = dispatch->ScopeIndex; i < table->Count; i++)
        {
            if (ControlPc >= dispatch->ImageBase + table->ScopeRecord[i].BeginAddress &&
                ControlPc < dispatch->ImageBase + table->ScopeRecord[i].EndAddress)
            {
                PTERMINATION_HANDLER handler;

                if (table->ScopeRecord[i].JumpTarget) continue;

                if (rec->ExceptionFlags & EH_TARGET_UNWIND &&
                    dispatch->TargetIp >= dispatch->ImageBase + table->ScopeRecord[i].BeginAddress &&
                    dispatch->TargetIp < dispatch->ImageBase + table->ScopeRecord[i].EndAddress)
                {
                    break;
                }

                handler = (PTERMINATION_HANDLER)(dispatch->ImageBase + table->ScopeRecord[i].HandlerAddress);
                dispatch->ScopeIndex = i+1;

                TRACE( "calling __finally %p frame %p\n", handler, frame );
#if defined(__aarch64__) || defined(__arm__)
                __C_ExecuteTerminationHandler( TRUE, frame, handler, dispatch->NonVolatileRegisters );
#else /* __x86_64__ */
                handler( TRUE, frame );
#endif
            }
        }
        return ExceptionContinueSearch;
    }

    for (i = dispatch->ScopeIndex; i < table->Count; i++)
    {
        if (ControlPc >= dispatch->ImageBase + table->ScopeRecord[i].BeginAddress &&
            ControlPc < dispatch->ImageBase + table->ScopeRecord[i].EndAddress)
        {
            if (!table->ScopeRecord[i].JumpTarget) continue;
            if (table->ScopeRecord[i].HandlerAddress != EXCEPTION_EXECUTE_HANDLER)
            {
                EXCEPTION_POINTERS ptrs;
                PEXCEPTION_FILTER filter;
                int filter_ret;

                filter = (PEXCEPTION_FILTER)(dispatch->ImageBase + table->ScopeRecord[i].HandlerAddress);
                ptrs.ExceptionRecord = rec;
                ptrs.ContextRecord = context;
                TRACE( "calling filter %p ptrs %p frame %p\n", filter, &ptrs, frame );
#if defined(__aarch64__) || defined(__arm__)
                filter_ret = __C_ExecuteExceptionFilter( &ptrs, frame, filter, dispatch->NonVolatileRegisters );
#else /* __x86_64__ */
                filter_ret = filter( &ptrs, frame );
#endif
                switch (filter_ret)
                {
                case EXCEPTION_EXECUTE_HANDLER:
                    break;
                case EXCEPTION_CONTINUE_SEARCH:
                    continue;
                case EXCEPTION_CONTINUE_EXECUTION:
                    return ExceptionContinueExecution;
                }
            }
            TRACE( "unwinding to target %p\n", (void *)(dispatch->ImageBase + table->ScopeRecord[i].JumpTarget) );
            RtlUnwindEx( frame, (char *)dispatch->ImageBase + table->ScopeRecord[i].JumpTarget,
                         rec, 0, dispatch->ContextRecord, dispatch->HistoryTable );
        }
    }
    return ExceptionContinueSearch;
}

static inline ULONG hash_pointers( void **ptrs, ULONG count )
{
    /* Based on MurmurHash2, which is in the public domain */
    static const ULONG m = 0x5bd1e995;
    static const ULONG r = 24;
    ULONG hash = count * sizeof(void*);
    for (; count > 0; ptrs++, count--)
    {
        ULONG_PTR data = (ULONG_PTR)*ptrs;
        ULONG k1 = (ULONG)(data & 0xffffffff);
#if defined(__x86_64__) || defined(__aarch64__)
        ULONG k2 = (ULONG)(data >> 32);
#endif
        k1 *= m;
        k1 = (k1 ^ (k1 >> r)) * m;
        hash = (hash * m) ^ k1;
#if defined(__x86_64__) || defined(__aarch64__)
        k2 *= m;
        k2 = (k2 ^ (k2 >> r)) * m;
        hash = (hash * m) ^ k2;
#endif
    }
    hash = (hash ^ (hash >> 13)) * m;
    return hash ^ (hash >> 15);
}

/*************************************************************************
 *             RtlCaptureStackBackTrace (NTDLL.@)
 */
USHORT WINAPI RtlCaptureStackBackTrace( ULONG skip, ULONG count, PVOID *buffer, ULONG *hash )
{
    UNWIND_HISTORY_TABLE table;
    DISPATCHER_CONTEXT dispatch;
    CONTEXT context;
    NTSTATUS status;
    ULONG i;
    USHORT num_entries = 0;

    TRACE( "(%lu, %lu, %p, %p)\n", skip, count, buffer, hash );

    RtlCaptureContext( &context );
    DISPATCHER_TARGET(&dispatch) = 0;
    dispatch.ContextRecord       = &context;
    dispatch.HistoryTable        = &table;
    if (hash) *hash = 0;
    for (i = 0; i < skip + count; i++)
    {
        status = virtual_unwind( UNW_FLAG_NHANDLER, &dispatch, &context );
        if (status != STATUS_SUCCESS) return i;

        if (!dispatch.EstablisherFrame) break;

        if (!is_valid_frame(dispatch.EstablisherFrame))
        {
            ERR( "invalid frame %p (%p-%p)\n", (void *)dispatch.EstablisherFrame,
                 NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
            break;
        }

        if (CTX_REG_SP(&context) == (ULONG_PTR)NtCurrentTeb()->Tib.StackBase) break;

        if (i >= skip) buffer[num_entries++] = (void *)CTX_REG_SP(&context);
    }
    if (hash && num_entries > 0) *hash = hash_pointers( buffer, num_entries );
    TRACE( "captured %hu frames\n", num_entries );
    return num_entries;
}

#endif  /* __x86_64__ || __arm__ || __aarch64__ */
