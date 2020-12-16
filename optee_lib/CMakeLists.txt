# // SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
#  Author: Jorge Ramirez <jorge@foundries.io>
#
#
# Build AARCH64
#  $ mkdir build
#  $ cd build
#  $ cmake -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc -DOPTEE_TREE=/path/to/optee/ ..
#  $ make CFLAGS="-mstrict-align -mgeneral-regs-only"
#
# Build ARM
#  $ mkdir build
#  $ cd build
#  $ cmake -DCMAKE_C_COMPILER=arm-linux-gnueabi-gcc -DOPTEE_TREE=/path/to/optee/ ..
#  $ make
#
# Library will be installed in optee_lib/build/libse050.a
#
# This stack has been integrated in OP-TEE and validated on iMX8mm and iMX6ull platforms fitted with the ARD SE050
# Foundries.io
#
#            _  _
#           | \/ |
#        \__|____|__/
#          |  o  o|           Thumbs Up
#          |___\/_|_____||_
#          |       _____|__|
#          |      |
#          |______|
#          | |  | |
#          | |  | |
#          |_|  |_|
#
#

CMAKE_MINIMUM_REQUIRED(VERSION 3.5.0)
project(se050)

set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} ${FLAGS} "-std=gnu99 \
                                    -fdiagnostics-show-option \
                                    -Wall -Os \
                                    -ffunction-sections -fdata-sections \
                                    -pipe -g3 -fpie")
FILE(
    GLOB
    SOURCES
     ../hostlib/hostLib/libCommon/smCom/smComT1oI2C.c
     ../hostlib/hostLib/libCommon/smCom/T1oI2C/phNxpEse_Api.c
     ../hostlib/hostLib/libCommon/smCom/T1oI2C/phNxpEseProto7816_3.c
     ../hostlib/hostLib/libCommon/infra/sm_connect.c
     ../hostlib/hostLib/libCommon/infra/sm_apdu.c
     ../hostlib/hostLib/libCommon/infra/global_platf.c
     ../hostlib/hostLib/libCommon/nxScp/nxScp03_Com.c
     ../hostlib/hostLib/se05x_03_xx_xx/se05x_APDU.c
     ../hostlib/hostLib/se05x/src/se05x_mw.c
     ../hostlib/hostLib/se05x/src/se05x_tlv.c
     ../hostlib/hostLib/se05x/src/se05x_ECC_curves.c
     ../sss/src/fsl_sss_util_rsa_sign_utils.c
     ../sss/src/fsl_sss_util_asn1_der.c
     ../sss/src/se05x/fsl_sss_se05x_policy.c
     ../sss/src/se05x/fsl_sss_se05x_mw.c
     ../sss/src/se05x/fsl_sss_se05x_apis.c
     ../sss/src/se05x/fsl_sss_se05x_scp03.c
     glue/stubs.c
     glue/wraps.c
     glue/i2c.c
     glue/smCom.c
     glue/user.c
     glue/der.c
)

add_library(${PROJECT_NAME} ${SOURCES})

FILE(
    GLOB
    INC_DIR
    ${OPTEE_TREE}/lib/libutils/ext/include
    ${OPTEE_TREE}/lib/libutee/include
    ${OPTEE_TREE}/core/arch/arm/include
    ${OPTEE_TREE}/core/include
    ../optee_lib/glue/include
    ../sss/inc
    ../sss/port/default
    ../sss/ex/src
    ../sss/ex/inc
    ../hostlib/hostLib/inc
    ../hostlib/hostLib/libCommon/infra
    ../hostlib/hostLib/libCommon/smCom
    ../hostlib/hostLib/libCommon/smCom/T1oI2C
    ../hostlib/hostLib/se05x_03_xx_xx
    ../hostlib/hostLib/platform/inc
    ../hostlib/hostLib/libCommon/smCom
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC
    ../
    ${INC_DIR}
    )

# Plug and Trust definitions
ADD_DEFINITIONS(-DSSS_USE_FTR_FILE)
ADD_DEFINITIONS(-DSMCOM_T1oI2C)
ADD_DEFINITIONS(-DT1oI2C)
ADD_DEFINITIONS(-DT1oI2C_UM11225)
ADD_DEFINITIONS(-DAX_EMBEDDED=1)
ADD_DEFINITIONS(-DVERBOSE_APDU_LOGS=0)
