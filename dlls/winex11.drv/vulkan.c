/* X11DRV Vulkan implementation
 *
 * Copyright 2017 Roderick Colenbrander
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

/* NOTE: If making changes here, consider whether they should be reflected in
 * the other drivers. */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"

#include "wine/debug.h"
#include "x11drv.h"
#include "xcomposite.h"

#include "wine/vulkan.h"
#include "wine/vulkan_driver.h"

WINE_DEFAULT_DEBUG_CHANNEL(vulkan);

#ifdef SONAME_LIBVULKAN

#define VK_STRUCTURE_TYPE_XLIB_SURFACE_CREATE_INFO_KHR 1000004000

typedef struct VkXlibSurfaceCreateInfoKHR
{
    VkStructureType sType;
    const void *pNext;
    VkXlibSurfaceCreateFlagsKHR flags;
    Display *dpy;
    Window window;
} VkXlibSurfaceCreateInfoKHR;

static VkResult (*pvkCreateXlibSurfaceKHR)(VkInstance, const VkXlibSurfaceCreateInfoKHR *, const VkAllocationCallbacks *, VkSurfaceKHR *);
static VkBool32 (*pvkGetPhysicalDeviceXlibPresentationSupportKHR)(VkPhysicalDevice, uint32_t, Display *, VisualID);

static const struct vulkan_driver_funcs x11drv_vulkan_driver_funcs;

struct x11drv_vulkan_surface
{
    Window window;
    RECT rect;

    BOOL offscreen;
    HDC hdc_src;
    HDC hdc_dst;
    BOOL other_process;
};

static void vulkan_surface_destroy( HWND hwnd, struct x11drv_vulkan_surface *surface )
{
    destroy_client_window( hwnd, surface->window );
    if (surface->hdc_dst) NtGdiDeleteObjectApp( surface->hdc_dst );
    if (surface->hdc_src) NtGdiDeleteObjectApp( surface->hdc_src );
    free( surface );
}

static RECT get_client_rect( HWND hwnd, BOOL raw )
{
    UINT dpi = NtUserGetDpiForWindow( hwnd );
    RECT rect;

    NtUserGetClientRect( hwnd, &rect, dpi );
    if (!raw) return rect;
    rect = map_rect_virt_to_raw_for_monitor( NtUserMonitorFromWindow( hwnd, MONITOR_DEFAULTTONEAREST ), rect, dpi );
    OffsetRect( &rect, -rect.left, -rect.top );
    return rect;
}

static BOOL disable_opwr(void)
{
    static int disable = -1;

    if (disable == -1)
    {
        const char *e = getenv( "WINE_DISABLE_VULKAN_OPWR" );
        disable = e && atoi( e );
    }
    return disable;
}

static VkResult X11DRV_vulkan_surface_create( HWND hwnd, VkInstance instance, VkSurfaceKHR *handle, void **private )
{
    VkXlibSurfaceCreateInfoKHR info =
    {
        .sType = VK_STRUCTURE_TYPE_XLIB_SURFACE_CREATE_INFO_KHR,
        .dpy = gdi_display,
    };
    struct x11drv_vulkan_surface *surface;
    BOOL enable_fshack = enable_fullscreen_hack( hwnd, FALSE );
    DWORD hwnd_pid, hwnd_thread_id;

    TRACE( "%p %p %p %p\n", hwnd, instance, handle, private );

    if (!(surface = calloc(1, sizeof(*surface))))
    {
        ERR("Failed to allocate vulkan surface for hwnd=%p\n", hwnd);
        return VK_ERROR_OUT_OF_HOST_MEMORY;
    }
    surface->rect = get_client_rect( hwnd, enable_fshack );

    hwnd_thread_id = NtUserGetWindowThread(hwnd, &hwnd_pid);
    if (hwnd_thread_id && hwnd_pid != GetCurrentProcessId())
    {
        XSetWindowAttributes attr;
        RECT rect = surface->rect;
        unsigned int width, height;

        WARN("Other process window %p.\n", hwnd);

        if (disable_opwr() && hwnd != NtUserGetDesktopWindow())
        {
            ERR( "HACK: Failing surface creation for other process window %p.\n", hwnd );
            free( surface );
            return VK_ERROR_OUT_OF_HOST_MEMORY;
        }

        width = max( rect.right - rect.left, 1 );
        height = max( rect.bottom - rect.top, 1 );
        attr.colormap = default_colormap;
        attr.bit_gravity = NorthWestGravity;
        attr.win_gravity = NorthWestGravity;
        attr.backing_store = NotUseful;
        attr.border_pixel = 0;
        surface->window = XCreateWindow( gdi_display, get_dummy_parent(), 0, 0, width, height, 0, default_visual.depth, InputOutput,
                                         default_visual.visual, CWBitGravity | CWWinGravity | CWBackingStore | CWColormap | CWBorderPixel, &attr );
        if (surface->window)
        {
            XMapWindow( gdi_display, surface->window );
            XSync( gdi_display, False );
            surface->other_process = TRUE;
        }
    }

    if (!surface->window && !(surface->window = create_client_window( hwnd, surface->rect, &default_visual, default_colormap )))
    {
        ERR("Failed to allocate client window for hwnd=%p\n", hwnd);
        free( surface );
        return VK_ERROR_OUT_OF_HOST_MEMORY;
    }

    info.window = surface->window;
    if (pvkCreateXlibSurfaceKHR( instance, &info, NULL /* allocator */, handle ))
    {
        ERR("Failed to create Xlib surface\n");
        vulkan_surface_destroy( hwnd, surface );
        return VK_ERROR_OUT_OF_HOST_MEMORY;
    }

    *private = (void *)surface;

    TRACE("Created surface 0x%s, private %p\n", wine_dbgstr_longlong(*handle), *private);
    return VK_SUCCESS;
}

static void X11DRV_vulkan_surface_destroy( HWND hwnd, void *private )
{
    struct x11drv_vulkan_surface *surface = private;

    TRACE( "%p %p\n", hwnd, private );

    vulkan_surface_destroy( hwnd, surface );
}

static void X11DRV_vulkan_surface_detach( HWND hwnd, void *private )
{
    struct x11drv_vulkan_surface *surface = private;
    Window client_window = surface->window;
    struct x11drv_win_data *data;

    TRACE( "%p %p\n", hwnd, private );

    if ((data = get_win_data( hwnd )))
    {
        detach_client_window( data, client_window );
        release_win_data( data );
    }
}

static void vulkan_surface_update_size( HWND hwnd, struct x11drv_vulkan_surface *surface )
{
    BOOL enable_fshack = enable_fullscreen_hack( hwnd, FALSE );
    XWindowChanges changes;
    RECT rect;

    rect = get_client_rect( hwnd, enable_fshack );
    if (EqualRect( &surface->rect, &rect )) return;

    changes.width  = min( max( 1, rect.right ), 65535 );
    changes.height = min( max( 1, rect.bottom ), 65535 );
    XConfigureWindow( gdi_display, surface->window, CWWidth | CWHeight, &changes );
    surface->rect = rect;
}

static void vulkan_surface_update_offscreen( HWND hwnd, struct x11drv_vulkan_surface *surface )
{
    BOOL offscreen = needs_offscreen_rendering( hwnd, FALSE, FALSE );
    struct x11drv_win_data *data;

    if (surface->other_process) offscreen = TRUE;
    if (offscreen == surface->offscreen)
    {
        if (!offscreen && (data = get_win_data( hwnd )))
        {
            attach_client_window( data, surface->window );
            release_win_data( data );
        }
        return;
    }
    surface->offscreen = offscreen;

    if (!surface->offscreen)
    {
#ifdef SONAME_LIBXCOMPOSITE
        if (usexcomposite) pXCompositeUnredirectWindow( gdi_display, surface->window, CompositeRedirectManual );
#endif
        if (surface->hdc_dst)
        {
            NtGdiDeleteObjectApp( surface->hdc_dst );
            surface->hdc_dst = NULL;
        }
        if (surface->hdc_src)
        {
            NtGdiDeleteObjectApp( surface->hdc_src );
            surface->hdc_src = NULL;
        }
    }
    else
    {
        static const WCHAR displayW[] = {'D','I','S','P','L','A','Y'};
        UNICODE_STRING device_str = RTL_CONSTANT_STRING(displayW);
        surface->hdc_dst = NtGdiOpenDCW( &device_str, NULL, NULL, 0, TRUE, NULL, NULL, NULL );
        surface->hdc_src = NtGdiOpenDCW( &device_str, NULL, NULL, 0, TRUE, NULL, NULL, NULL );
        set_dc_drawable( surface->hdc_src, surface->window, &surface->rect, IncludeInferiors );
#ifdef SONAME_LIBXCOMPOSITE
        if (usexcomposite) pXCompositeRedirectWindow( gdi_display, surface->window, CompositeRedirectManual );
#endif
    }

    if ((data = get_win_data( hwnd )))
    {
        if (surface->offscreen) detach_client_window( data, surface->window );
        else attach_client_window( data, surface->window );
        release_win_data( data );
    }
}

static void X11DRV_vulkan_surface_update( HWND hwnd, void *private )
{
    struct x11drv_vulkan_surface *surface = private;

    TRACE( "%p %p\n", hwnd, private );

    vulkan_surface_update_size( hwnd, surface );
    vulkan_surface_update_offscreen( hwnd, surface );
}

static int force_present_to_surface(void)
{
    static int cached = -1;

    if (cached == -1)
    {
        const char *sgi = getenv( "SteamGameId" );

        cached = sgi &&
                 (
                    !strcmp(sgi, "803600")
                 );
    }
    return cached;
}

static void X11DRV_vulkan_surface_presented( HWND hwnd, void *private, VkResult result )
{
    struct x11drv_vulkan_surface *surface = private;
    struct window_surface *win_surface;
    struct x11drv_win_data *data;
    RECT rect_dst, rect;
    Drawable window;
    HWND toplevel;
    HRGN region;
    UINT dpi;
    HDC hdc;

    vulkan_surface_update_size( hwnd, surface );
    vulkan_surface_update_offscreen( hwnd, surface );

    if (!surface->offscreen) return;

    if (force_present_to_surface() && (win_surface = window_surface_get( hwnd )))
    {
        TRACE("blitting to surface win_surface %p.\n", win_surface);
        if (!(hdc = NtUserGetDCEx( hwnd, 0, DCX_CACHE | DCX_USESTYLE ))) return;
        NtGdiStretchBlt( hdc, 0, 0, surface->rect.right - surface->rect.left, surface->rect.bottom - surface->rect.top,
                         surface->hdc_src, 0, 0, surface->rect.right, surface->rect.bottom, SRCCOPY, 0 );
        NtUserReleaseDC( hwnd, hdc );
        window_surface_release( win_surface );
        return;
    }

    toplevel = NtUserGetAncestor( hwnd, GA_ROOT );
    dpi = NtUserGetDpiForWindow( hwnd );
    NtUserGetClientRect( hwnd, &rect_dst, dpi );
    NtUserMapWindowPoints( hwnd, toplevel, (POINT *)&rect_dst, 2, dpi );
    if (IsRectEmpty( &rect_dst ) || IsRectEmpty( &surface->rect )) return;
    rect_dst = map_rect_virt_to_raw_for_monitor( NtUserMonitorFromWindow( toplevel, MONITOR_DEFAULTTONEAREST ), rect_dst, dpi );
    if ((data = get_win_data( toplevel )))
    {
        OffsetRect( &rect_dst, data->rects.client.left - data->rects.visible.left,
                    data->rects.client.top - data->rects.visible.top );
        release_win_data( data );
    }

    if (!(hdc = NtUserGetDCEx( hwnd, 0, DCX_CACHE | DCX_USESTYLE ))) return;
    window = X11DRV_get_whole_window( toplevel );
    region = get_dc_monitor_region( hwnd, hdc );

    if (get_dc_drawable( surface->hdc_dst, &rect ) != window || !EqualRect( &rect, &rect_dst ))
        set_dc_drawable( surface->hdc_dst, window, &rect_dst, IncludeInferiors );
    if (region) NtGdiExtSelectClipRgn( surface->hdc_dst, region, RGN_COPY );

    NtGdiStretchBlt( surface->hdc_dst, 0, 0, rect_dst.right - rect_dst.left, rect_dst.bottom - rect_dst.top,
                     surface->hdc_src, 0, 0, surface->rect.right, surface->rect.bottom, SRCCOPY, 0 );

    if (region) NtGdiDeleteObjectApp( region );
    if (hdc) NtUserReleaseDC( hwnd, hdc );
}

static BOOL X11DRV_vulkan_surface_enable_fshack( HWND hwnd, void *private )
{
    return enable_fullscreen_hack( hwnd, FALSE );
}

static VkBool32 X11DRV_vkGetPhysicalDeviceWin32PresentationSupportKHR(VkPhysicalDevice phys_dev,
        uint32_t index)
{
    TRACE("%p %u\n", phys_dev, index);

    return pvkGetPhysicalDeviceXlibPresentationSupportKHR(phys_dev, index, gdi_display,
            default_visual.visual->visualid);
}

static const char *X11DRV_get_host_surface_extension(void)
{
    return "VK_KHR_xlib_surface";
}

static const struct vulkan_driver_funcs x11drv_vulkan_driver_funcs =
{
    .p_vulkan_surface_create = X11DRV_vulkan_surface_create,
    .p_vulkan_surface_destroy = X11DRV_vulkan_surface_destroy,
    .p_vulkan_surface_detach = X11DRV_vulkan_surface_detach,
    .p_vulkan_surface_update = X11DRV_vulkan_surface_update,
    .p_vulkan_surface_presented = X11DRV_vulkan_surface_presented,
    .p_vulkan_surface_enable_fshack = X11DRV_vulkan_surface_enable_fshack,

    .p_vkGetPhysicalDeviceWin32PresentationSupportKHR = X11DRV_vkGetPhysicalDeviceWin32PresentationSupportKHR,
    .p_get_host_surface_extension = X11DRV_get_host_surface_extension,
};

UINT X11DRV_VulkanInit( UINT version, void *vulkan_handle, const struct vulkan_driver_funcs **driver_funcs )
{
    if (version != WINE_VULKAN_DRIVER_VERSION)
    {
        ERR( "version mismatch, win32u wants %u but driver has %u\n", version, WINE_VULKAN_DRIVER_VERSION );
        return STATUS_INVALID_PARAMETER;
    }

#define LOAD_FUNCPTR( f ) if (!(p##f = dlsym( vulkan_handle, #f ))) return STATUS_PROCEDURE_NOT_FOUND;
    LOAD_FUNCPTR( vkCreateXlibSurfaceKHR );
    LOAD_FUNCPTR( vkGetPhysicalDeviceXlibPresentationSupportKHR );
#undef LOAD_FUNCPTR

    *driver_funcs = &x11drv_vulkan_driver_funcs;
    return STATUS_SUCCESS;
}

#else /* No vulkan */

UINT X11DRV_VulkanInit( UINT version, void *vulkan_handle, const struct vulkan_driver_funcs **driver_funcs )
{
    ERR( "Wine was built without Vulkan support.\n" );
    return STATUS_NOT_IMPLEMENTED;
}

#endif /* SONAME_LIBVULKAN */
