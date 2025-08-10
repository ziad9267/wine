#!/bin/bash
current_dir_name="${PWD##*/}"
if [ "$current_dir_name" = "build" ]; then
    echo "Current directory is 'build'. Proceeding to build native wine-tools..."
    
    # Remove existing build folders
    rm -rf ../wine-tools-build
    rm -rf ../wine-tools
    
    # Prepare environment
    mkdir ../wine-tools-build
    mkdir ../wine-tools
    cd ../wine-tools-build
    
    # Prepare wine-tools-build directory and wine-tools folder
    ../configure --without-x --without-gstreamer --without-vulkan --without-wayland --enable-wineandroid_drv=no 
    cp -r ../wine-tools-build/* ../wine-tools
    
    # Build native wine-tools
    cd ../wine-tools/tools/winebuild && make -j$(nproc)
    cd ../wrc && make -j$(nproc)
    cd ../widl && make -j$(nproc)
    cd ../winegcc && make -j$(nproc)
    cd ../sfnt2fon && make -j$(nproc)
    cd ../winedump && make -j$(nproc)
    cd ../winemaker && make -j$(nproc)
    cd ../wmc && make -j$(nproc)
    gcc ../../../tools/make_xftmpl.c -I../../../wine-tools-build/include -I../../../include -o ../../../wine-tools/tools/make_xftmpl
    cp ../../../tools/wineapploader.in ../../../wine-tools/tools/wineapploader
    chmod +x ../../../wine-tools/tools/wineapploader

    # clean-up
    cd ../../
    current_dir_name="${PWD##*/}"
    if [ "$current_dir_name" = "wine-tools" ]; then
        echo "Current directory is 'wine-tools'. Proceeding with clean-up..."
        find . -maxdepth 1 -mindepth 1 ! -name "tools" -exec rm -rf {} +
        
        echo 'Returning to main build directory'
        cd ../build
        echo 'Ready to configure proton-9.0-arm64ec!'
    else
        echo "Current directory is not 'wine-tools' ($current_dir_name). Aborting to prevent accidental data loss."
    fi
else
    echo "Current directory is not 'build'." 
    echo "This script must be run from the 'build' directory of your Wine source repo." 
    echo "Create the 'build' directory."
    echo "Copy in this file."
    echo "Enter the 'build' directory"
    echo "Run this script again with './build-wine-tools.sh'"
fi
