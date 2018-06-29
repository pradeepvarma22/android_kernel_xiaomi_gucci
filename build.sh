#!/bin/sh

#
 # Copyright © 2016, Pradeep_7 <pradeepvarma107@gmail.com>
 #
 # Custom build script
 #
 # This software is licensed under the terms of the GNU General Public
 # License version 2, as published by the Free Software Foundation, and
 # may be copied, distributed, and modified under those terms.
 #
 # This program is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 # GNU General Public License for more details.
 #
 # Use it I also Have kanged it from somewhere

KERNEL_DIR=$PWD
Anykernel_DIR=$KERNEL_DIR/Anykernel2/gucci
TOOLCHAINDIR=$(pwd)/toolchain/arm-eabi-4.8
DATE=$(date +"%d%m%Y")
KERNEL_NAME="Pradeep_7"
DEVICE="####"
TYPE="   "
FINAL_ZIP="$KERNEL_NAME""$DEVICE""$DATE""$TYPE""$VER".zip

echo ""
echo "#####################started Compiling Kernel -Pradeep_7/#####################"
echo ""





echo ""
echo "making out folder clean and making mrproper"
echo ""
make clean
make mrproper
make ARCH=arm O=$(pwd)/out mrproper
make ARCH=arm O=../out clean







echo ""
echo "#####################exporting paths for arm-eabi-4.8#####################"
echo ""
export PATH=$(pwd)/toolchain/arm-eabi-4.8/bin:$PATH 		
export CROSS_COMPILE=$(pwd)/toolchain/arm-eabi-4.8/bin/arm-eabi-









echo ""
echo "#####################Gucci_defconfig#####################"
echo ""


make ARCH=arm O=$(pwd)/out gucci_defconfig
make ARCH=arm O=$(pwd)/out -j7
export KBUILD_BUILD_USER="7"
export KBUILD_BUILD_HOST="Pradeep"




if [ -e  out/arch/arm/boot/zImage ];
then
echo "Kernel compilation completed"
cp $KERNEL_DIR/out/arch/arm/boot/zImage $Anykernel_DIR/
cd $Anykernel_DIR
echo "Making Flashable zip"
echo "Generating changelog"
git log --graph --pretty=format:'%s' --abbrev-commit -n 200  > changelog.txt
echo "Changelog generated"
zip -r9 $FINAL_ZIP * -x *.zip $FINAL_ZIP
echo "Flashable zip Created"
echo "Uploading file"
curl -H "Max-Downloads: 1" -H "Max-Days: 1" --upload-file $FINAL_ZIP https://transfer.sh/$FINAL_ZIP
else
echo "Kernel not compiled,fix errors and compile again"
fi;
