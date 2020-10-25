.. title:

OP-TEE Enabled Plug and Trust Library
=====================================

This repository provides the functionality required by a Trusted Execution Environment (in this case OP-TEE, v3.11 released on Oct 16 2020) to access the `NXP EdgeLock™ SE050: Plug & Trust Secure Element`.

The relevant OP-TEE driver can be found at https://github.com/OP-TEE/optee_os/pull/4178.

The stack has been validated on iMX8mm and iMX6ull platforms fitted with the ARD SE050 https://www.nxp.com/products/security-and-authentication/authentication/edgelock-se050-development-kit:OM-SE050X for the following operations::

   * RSA 2048, 4096
   * AES CTR 
   * RNG
   * SCP03 (i2c communications between the processor and the device are encrypted)
   * DieID generation
   * cryptoki integration


Building the library
--------------------

From the optee_lib directory do as follows:

For arm64::
 
 $ mkdir build
 $ cd build
 $ cmake -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc -DOPTEE_TREE=/path/to/optee/ ..
 $ make CFLAGS="-mstrict-align -mgeneral-regs-only"

For arm::

 $ mkdir build
 $ cd build
 $ cmake -DCMAKE_C_COMPILER=arm-linux-gnueabi-gcc -DOPTEE_TREE=/path/to/optee/ ..
 $ make

Additional Information
-----------------------
For information on other ways of using this stack please check the original `README` 

.. _README link: ./README.original.rst
.. _NXP EdgeLock™ SE050 Plug & Trust Secure Element link: https://www.nxp.com/docs/en/data-sheet/SE050-DATASHEET.pdf 


Have fun::

            _  _
           | \/ |
        \__|____|__/
          |  o  o|           Thumbs Up
          |___\/_|_____||_
          |       _____|__|
          |      |
          |______|
          | |  | |
          | |  | |
          |_|  |_|


Foundries.io
