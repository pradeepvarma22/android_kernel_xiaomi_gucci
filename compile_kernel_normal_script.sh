#!/bin/bash

#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#
#### USAGE:
#### ./compile_kernel_normal_script.sh
#### [clean] - clean is Included
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#
#####
### Prepared by:
### Pradeep_7 (pradeepvarma107@gmail.com)
#####
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#

### This script is to compile Official kernel for MiUi7/8

echo "***************!!!!! Prepared By - Pradeep_7  !!!!!********************"

echo "***************!!!!!  CLEAN  !!!!!********************"
make clean

echo "***************!!!!! Make Mrproper!!!!!********************"
make mrproper


echo "***************!!!!! Platform!!!!!********************"
echo "***************!!!!! export ARCH=arm /
export SUBARCH=arm /
TOOL_CHAIN_ARM=arm-eabi- /!!!!!********************"

export ARCH=arm
export SUBARCH=arm
TOOL_CHAIN_ARM=arm-eabi-


echo "***************!!!!!Tool Chain $ Making deconfig!!!!!********************"
echo "***************!!!!! export PATH=$(pwd)/toolchain/arm-eabi-4.8/bin:$PATH

export CROSS_COMPILE=$(pwd)/toolchain/arm-eabi-4.8/bin/arm-eabi-


make ARCH=$ARCH CROSS_COMPILE=toolchain/arm-eabi-4.8/bin/arm-eabi- gucci_defconfig!!!!!********************"

export PATH=$(pwd)/toolchain/arm-eabi-4.8/bin:$PATH

export CROSS_COMPILE=$(pwd)/toolchain/arm-eabi-4.8/bin/arm-eabi-

make ARCH=$ARCH CROSS_COMPILE=toolchain/arm-eabi-4.8/bin/arm-eabi- gucci_defconfig

echo "***************!!!!! Make -j7!!!!!********************"
make -j7

