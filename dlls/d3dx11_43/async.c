/*
 * Copyright 2016 Matteo Bruni for CodeWeavers
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

#define COBJMACROS
#include "d3dx11.h"
#include "d3dcompiler.h"
#include "dxhelpers.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(d3dx);

struct asyncdataloader
{
    ID3DX11DataLoader ID3DX11DataLoader_iface;

    union
    {
        struct
        {
            WCHAR *path;
        } file;
        struct
        {
            HMODULE module;
            HRSRC rsrc;
        } resource;
    } u;
    void *data;
    DWORD size;
};

static inline struct asyncdataloader *impl_from_ID3DX11DataLoader(ID3DX11DataLoader *iface)
{
    return CONTAINING_RECORD(iface, struct asyncdataloader, ID3DX11DataLoader_iface);
}

static HRESULT WINAPI memorydataloader_Load(ID3DX11DataLoader *iface)
{
    TRACE("iface %p.\n", iface);
    return S_OK;
}

static HRESULT WINAPI memorydataloader_Decompress(ID3DX11DataLoader *iface, void **data, SIZE_T *size)
{
    struct asyncdataloader *loader = impl_from_ID3DX11DataLoader(iface);

    TRACE("iface %p, data %p, size %p.\n", iface, data, size);

    *data = loader->data;
    *size = loader->size;

    return S_OK;
}

static HRESULT WINAPI memorydataloader_Destroy(ID3DX11DataLoader *iface)
{
    struct asyncdataloader *loader = impl_from_ID3DX11DataLoader(iface);

    TRACE("iface %p.\n", iface);

    free(loader);
    return S_OK;
}

static const ID3DX11DataLoaderVtbl memorydataloadervtbl =
{
    memorydataloader_Load,
    memorydataloader_Decompress,
    memorydataloader_Destroy
};

static HRESULT WINAPI filedataloader_Load(ID3DX11DataLoader *iface)
{
    struct asyncdataloader *loader = impl_from_ID3DX11DataLoader(iface);
    void *data;
    DWORD size;
    HRESULT hr;

    TRACE("iface %p.\n", iface);

    /* Always buffer file contents, even if Load() was already called. */
    if (FAILED((hr = load_file(loader->u.file.path, &data, &size))))
        return hr;

    free(loader->data);
    loader->data = data;
    loader->size = size;

    return S_OK;
}

static HRESULT WINAPI filedataloader_Decompress(ID3DX11DataLoader *iface, void **data, SIZE_T *size)
{
    struct asyncdataloader *loader = impl_from_ID3DX11DataLoader(iface);

    TRACE("iface %p, data %p, size %p.\n", iface, data, size);

    if (!loader->data)
        return E_FAIL;

    *data = loader->data;
    *size = loader->size;

    return S_OK;
}

static HRESULT WINAPI filedataloader_Destroy(ID3DX11DataLoader *iface)
{
    struct asyncdataloader *loader = impl_from_ID3DX11DataLoader(iface);

    TRACE("iface %p.\n", iface);

    free(loader->u.file.path);
    free(loader->data);
    free(loader);

    return S_OK;
}

static const ID3DX11DataLoaderVtbl filedataloadervtbl =
{
    filedataloader_Load,
    filedataloader_Decompress,
    filedataloader_Destroy
};

static HRESULT WINAPI resourcedataloader_Load(ID3DX11DataLoader *iface)
{
    struct asyncdataloader *loader = impl_from_ID3DX11DataLoader(iface);

    TRACE("iface %p.\n", iface);

    if (loader->data)
        return S_OK;

    return load_resource(loader->u.resource.module, loader->u.resource.rsrc,
            &loader->data, &loader->size);
}

static HRESULT WINAPI resourcedataloader_Decompress(ID3DX11DataLoader *iface, void **data, SIZE_T *size)
{
    struct asyncdataloader *loader = impl_from_ID3DX11DataLoader(iface);

    TRACE("iface %p, data %p, size %p.\n", iface, data, size);

    if (!loader->data)
        return E_FAIL;

    *data = loader->data;
    *size = loader->size;

    return S_OK;
}

static HRESULT WINAPI resourcedataloader_Destroy(ID3DX11DataLoader *iface)
{
    struct asyncdataloader *loader = impl_from_ID3DX11DataLoader(iface);

    TRACE("iface %p.\n", iface);

    free(loader);

    return S_OK;
}

static const ID3DX11DataLoaderVtbl resourcedataloadervtbl =
{
    resourcedataloader_Load,
    resourcedataloader_Decompress,
    resourcedataloader_Destroy
};

struct texture_info_processor
{
    ID3DX11DataProcessor ID3DX11DataProcessor_iface;
    D3DX11_IMAGE_INFO *info;
};

static inline struct texture_info_processor *impl_from_ID3DX11DataProcessor(ID3DX11DataProcessor *iface)
{
    return CONTAINING_RECORD(iface, struct texture_info_processor, ID3DX11DataProcessor_iface);
}

static HRESULT WINAPI texture_info_processor_Process(ID3DX11DataProcessor *iface, void *data, SIZE_T size)
{
    struct texture_info_processor *processor = impl_from_ID3DX11DataProcessor(iface);

    TRACE("iface %p, data %p, size %Iu.\n", iface, data, size);
    return get_image_info(data, size, processor->info);
}

static HRESULT WINAPI texture_info_processor_CreateDeviceObject(ID3DX11DataProcessor *iface, void **object)
{
    TRACE("iface %p, object %p.\n", iface, object);
    return S_OK;
}

static HRESULT WINAPI texture_info_processor_Destroy(ID3DX11DataProcessor *iface)
{
    struct texture_info_processor *processor = impl_from_ID3DX11DataProcessor(iface);

    TRACE("iface %p.\n", iface);

    free(processor);
    return S_OK;
}

static ID3DX11DataProcessorVtbl texture_info_processor_vtbl =
{
    texture_info_processor_Process,
    texture_info_processor_CreateDeviceObject,
    texture_info_processor_Destroy
};

struct texture_processor
{
    ID3DX11DataProcessor ID3DX11DataProcessor_iface;
    ID3D11Device *device;
    D3DX11_IMAGE_INFO img_info;
    D3DX11_IMAGE_LOAD_INFO load_info;
    D3D11_SUBRESOURCE_DATA *resource_data;
};

static inline struct texture_processor *texture_processor_from_ID3DX11DataProcessor(ID3DX11DataProcessor *iface)
{
    return CONTAINING_RECORD(iface, struct texture_processor, ID3DX11DataProcessor_iface);
}

static HRESULT WINAPI texture_processor_Process(ID3DX11DataProcessor *iface, void *data, SIZE_T size)
{
    struct texture_processor *processor = texture_processor_from_ID3DX11DataProcessor(iface);

    TRACE("iface %p, data %p, size %Iu.\n", iface, data, size);

    if (processor->resource_data)
    {
        WARN("Called multiple times.\n");
        free(processor->resource_data);
        processor->resource_data = NULL;
    }
    return load_texture_data(data, size, &processor->load_info, &processor->resource_data);
}

static HRESULT WINAPI texture_processor_CreateDeviceObject(ID3DX11DataProcessor *iface, void **object)
{
    struct texture_processor *processor = texture_processor_from_ID3DX11DataProcessor(iface);

    TRACE("iface %p, object %p.\n", iface, object);

    if (!processor->resource_data)
        return E_FAIL;

    return create_d3d_texture(processor->device, &processor->load_info,
            processor->resource_data, (ID3D11Resource **)object);
}

static HRESULT WINAPI texture_processor_Destroy(ID3DX11DataProcessor *iface)
{
    struct texture_processor *processor = texture_processor_from_ID3DX11DataProcessor(iface);

    TRACE("iface %p.\n", iface);

    ID3D11Device_Release(processor->device);
    free(processor->resource_data);
    free(processor);
    return S_OK;
}

static ID3DX11DataProcessorVtbl texture_processor_vtbl =
{
    texture_processor_Process,
    texture_processor_CreateDeviceObject,
    texture_processor_Destroy
};

struct srv_processor
{
    ID3DX11DataProcessor ID3DX11DataProcessor_iface;
    ID3DX11DataProcessor *texture_processor;
};

static inline struct srv_processor *srv_processor_from_ID3DX11DataProcessor(ID3DX11DataProcessor *iface)
{
    return CONTAINING_RECORD(iface, struct srv_processor, ID3DX11DataProcessor_iface);
}

static HRESULT WINAPI srv_processor_Process(ID3DX11DataProcessor *iface, void *data, SIZE_T size)
{
    struct srv_processor *processor = srv_processor_from_ID3DX11DataProcessor(iface);

    TRACE("iface %p, data %p, size %Iu.\n", iface, data, size);

    return ID3DX11DataProcessor_Process(processor->texture_processor, data, size);
}

static HRESULT WINAPI srv_processor_CreateDeviceObject(ID3DX11DataProcessor *iface, void **object)
{
    struct srv_processor *processor = srv_processor_from_ID3DX11DataProcessor(iface);
    struct texture_processor *tex_processor = texture_processor_from_ID3DX11DataProcessor(processor->texture_processor);
    ID3D11Resource *texture_resource;
    HRESULT hr;

    TRACE("iface %p, object %p.\n", iface, object);

    hr = ID3DX11DataProcessor_CreateDeviceObject(processor->texture_processor, (void **)&texture_resource);
    if (FAILED(hr))
        return hr;

    hr = ID3D11Device_CreateShaderResourceView(tex_processor->device, texture_resource, NULL,
            (ID3D11ShaderResourceView **)object);
    ID3D11Resource_Release(texture_resource);
    return hr;
}

static HRESULT WINAPI srv_processor_Destroy(ID3DX11DataProcessor *iface)
{
    struct srv_processor *processor = srv_processor_from_ID3DX11DataProcessor(iface);

    TRACE("iface %p.\n", iface);

    ID3DX11DataProcessor_Destroy(processor->texture_processor);
    free(processor);
    return S_OK;
}

static ID3DX11DataProcessorVtbl srv_processor_vtbl =
{
    srv_processor_Process,
    srv_processor_CreateDeviceObject,
    srv_processor_Destroy
};

HRESULT WINAPI D3DX11CompileFromMemory(const char *data, SIZE_T data_size, const char *filename,
        const D3D10_SHADER_MACRO *defines, ID3D10Include *include, const char *entry_point,
        const char *target, UINT sflags, UINT eflags, ID3DX11ThreadPump *pump, ID3D10Blob **shader,
        ID3D10Blob **error_messages, HRESULT *hresult)
{
    TRACE("data %s, data_size %Iu, filename %s, defines %p, include %p, entry_point %s, target %s, "
            "sflags %#x, eflags %#x, pump %p, shader %p, error_messages %p, hresult %p.\n",
            debugstr_an(data, data_size), data_size, debugstr_a(filename), defines, include,
            debugstr_a(entry_point), debugstr_a(target), sflags, eflags, pump, shader,
            error_messages, hresult);

    if (pump)
        FIXME("Unimplemented ID3DX11ThreadPump handling.\n");

    return D3DCompile(data, data_size, filename, defines, include, entry_point, target,
            sflags, eflags, shader, error_messages);
}

HRESULT WINAPI D3DX11CompileFromFileA(const char *filename, const D3D10_SHADER_MACRO *defines,
        ID3D10Include *include, const char *entry_point, const char *target, UINT sflags, UINT eflags,
        ID3DX11ThreadPump *pump, ID3D10Blob **shader, ID3D10Blob **error_messages, HRESULT *hresult)
{
    WCHAR filename_w[MAX_PATH];

    TRACE("filename %s, defines %p, include %p, entry_point %s, target %s, sflags %#x, "
            "eflags %#x, pump %p, shader %p, error_messages %p, hresult %p.\n",
            debugstr_a(filename), defines, include, debugstr_a(entry_point), debugstr_a(target),
            sflags, eflags, pump, shader, error_messages, hresult);

    MultiByteToWideChar(CP_ACP, 0, filename, -1, filename_w, ARRAY_SIZE(filename_w));

    return D3DX11CompileFromFileW(filename_w, defines, include, entry_point, target,
            sflags, eflags, pump, shader, error_messages, hresult);
}

HRESULT WINAPI D3DX11CompileFromFileW(const WCHAR *filename, const D3D10_SHADER_MACRO *defines,
        ID3D10Include *include, const char *entry_point, const char *target, UINT sflags, UINT eflags,
        ID3DX11ThreadPump *pump, ID3D10Blob **shader, ID3D10Blob **error_messages, HRESULT *hresult)
{
    HRESULT hr;

    TRACE("filename %s, defines %p, include %p, entry_point %s, target %s, sflags %#x, "
            "eflags %#x, pump %p, shader %p, error_messages %p, hresult %p.\n",
            debugstr_w(filename), defines, include, debugstr_a(entry_point), debugstr_a(target),
            sflags, eflags, pump, shader, error_messages, hresult);

    if (pump)
        FIXME("Unimplemented ID3DX11ThreadPump handling.\n");

    if (!include)
        include = D3D_COMPILE_STANDARD_FILE_INCLUDE;

    hr = D3DCompileFromFile(filename, defines, include, entry_point, target, sflags, eflags, shader, error_messages);
    if (hresult)
        *hresult = hr;

    return hr;
}

HRESULT WINAPI D3DX11CreateAsyncMemoryLoader(const void *data, SIZE_T data_size, ID3DX11DataLoader **loader)
{
    struct asyncdataloader *object;

    TRACE("data %p, data_size %Iu, loader %p.\n", data, data_size, loader);

    if (!data || !loader)
        return E_FAIL;

    object = calloc(1, sizeof(*object));
    if (!object)
        return E_OUTOFMEMORY;

    object->ID3DX11DataLoader_iface.lpVtbl = &memorydataloadervtbl;
    object->data = (void *)data;
    object->size = data_size;

    *loader = &object->ID3DX11DataLoader_iface;

    return S_OK;
}

HRESULT WINAPI D3DX11CreateAsyncFileLoaderA(const char *filename, ID3DX11DataLoader **loader)
{
    WCHAR *filename_w;
    HRESULT hr;
    int len;

    TRACE("filename %s, loader %p.\n", debugstr_a(filename), loader);

    if (!filename || !loader)
        return E_FAIL;

    len = MultiByteToWideChar(CP_ACP, 0, filename, -1, NULL, 0);
    filename_w = malloc(len * sizeof(*filename_w));
    MultiByteToWideChar(CP_ACP, 0, filename, -1, filename_w, len);

    hr = D3DX11CreateAsyncFileLoaderW(filename_w, loader);

    free(filename_w);

    return hr;
}

HRESULT WINAPI D3DX11CreateAsyncFileLoaderW(const WCHAR *filename, ID3DX11DataLoader **loader)
{
    struct asyncdataloader *object;

    TRACE("filename %s, loader %p.\n", debugstr_w(filename), loader);

    if (!filename || !loader)
        return E_FAIL;

    object = calloc(1, sizeof(*object));
    if (!object)
        return E_OUTOFMEMORY;

    object->ID3DX11DataLoader_iface.lpVtbl = &filedataloadervtbl;
    object->u.file.path = malloc((lstrlenW(filename) + 1) * sizeof(WCHAR));
    if (!object->u.file.path)
    {
        free(object);
        return E_OUTOFMEMORY;
    }
    lstrcpyW(object->u.file.path, filename);
    object->data = NULL;
    object->size = 0;

    *loader = &object->ID3DX11DataLoader_iface;

    return S_OK;
}

HRESULT WINAPI D3DX11CreateAsyncResourceLoaderA(HMODULE module, const char *resource, ID3DX11DataLoader **loader)
{
    struct asyncdataloader *object;
    HRSRC rsrc;
    HRESULT hr;

    TRACE("module %p, resource %s, loader %p.\n", module, debugstr_a(resource), loader);

    if (!loader)
        return E_FAIL;

    object = calloc(1, sizeof(*object));
    if (!object)
        return E_OUTOFMEMORY;

    if (FAILED((hr = load_resource_initA(module, resource, &rsrc))))
    {
        free(object);
        return hr;
    }

    object->ID3DX11DataLoader_iface.lpVtbl = &resourcedataloadervtbl;
    object->u.resource.module = module;
    object->u.resource.rsrc = rsrc;
    object->data = NULL;
    object->size = 0;

    *loader = &object->ID3DX11DataLoader_iface;

    return S_OK;
}

HRESULT WINAPI D3DX11CreateAsyncResourceLoaderW(HMODULE module, const WCHAR *resource, ID3DX11DataLoader **loader)
{
    struct asyncdataloader *object;
    HRSRC rsrc;
    HRESULT hr;

    TRACE("module %p, resource %s, loader %p.\n", module, debugstr_w(resource), loader);

    if (!loader)
        return E_FAIL;

    object = calloc(1, sizeof(*object));
    if (!object)
        return E_OUTOFMEMORY;

    if (FAILED((hr = load_resource_initW(module, resource, &rsrc))))
    {
        free(object);
        return hr;
    }

    object->ID3DX11DataLoader_iface.lpVtbl = &resourcedataloadervtbl;
    object->u.resource.module = module;
    object->u.resource.rsrc = rsrc;
    object->data = NULL;
    object->size = 0;

    *loader = &object->ID3DX11DataLoader_iface;

    return S_OK;
}

HRESULT WINAPI D3DX11CreateAsyncTextureInfoProcessor(D3DX11_IMAGE_INFO *info, ID3DX11DataProcessor **processor)
{
    struct texture_info_processor *object;

    TRACE("info %p, processor %p.\n", info, processor);

    if (!processor)
        return E_INVALIDARG;

    object = malloc(sizeof(*object));
    if (!object)
        return E_OUTOFMEMORY;

    object->ID3DX11DataProcessor_iface.lpVtbl = &texture_info_processor_vtbl;
    object->info = info;

    *processor = &object->ID3DX11DataProcessor_iface;
    return S_OK;
}

HRESULT WINAPI D3DX11CreateAsyncTextureProcessor(ID3D11Device *device,
        D3DX11_IMAGE_LOAD_INFO *load_info, ID3DX11DataProcessor **processor)
{
    struct texture_processor *object;

    TRACE("device %p, load_info %p, processor %p.\n", device, load_info, processor);

    if (!device || !processor)
        return E_INVALIDARG;

    object = calloc(1, sizeof(*object));
    if (!object)
        return E_OUTOFMEMORY;

    object->ID3DX11DataProcessor_iface.lpVtbl = &texture_processor_vtbl;
    object->device = device;
    ID3D11Device_AddRef(device);
    init_load_info(load_info, &object->load_info);
    if (!object->load_info.pSrcInfo)
        object->load_info.pSrcInfo = &object->img_info;

    *processor = &object->ID3DX11DataProcessor_iface;
    return S_OK;
}

HRESULT WINAPI D3DX11CreateAsyncShaderResourceViewProcessor(ID3D11Device *device,
        D3DX11_IMAGE_LOAD_INFO *load_info, ID3DX11DataProcessor **processor)
{
    struct srv_processor *object;
    HRESULT hr;

    TRACE("device %p, load_info %p, processor %p.\n", device, load_info, processor);

    if (!device || !processor)
        return E_INVALIDARG;

    object = calloc(1, sizeof(*object));
    if (!object)
        return E_OUTOFMEMORY;

    hr = D3DX11CreateAsyncTextureProcessor(device, load_info, &object->texture_processor);
    if (FAILED(hr))
    {
        free(object);
        return hr;
    }
    object->ID3DX11DataProcessor_iface.lpVtbl = &srv_processor_vtbl;
    *processor = &object->ID3DX11DataProcessor_iface;
    return S_OK;
}
