/**
 * Copyright (c) [2022] [pchom]
 * [MDS] is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 **/
#ifndef __MDS_BOOT_H__
#define __MDS_BOOT_H__

/* Include ----------------------------------------------------------------- */
#include "mds_def.h"
#include "algo_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Define ------------------------------------------------------------------ */
#ifndef MDS_BOOT_SWAP_SECTION
#define MDS_BOOT_SWAP_SECTION ".mds.boot"
#endif

#define MDS_BOOT_UPGRADE_MAGIC 0x9ADE

#define MDS_BOOT_CHKHASH_SIZE 0x20

/* Typedef ----------------------------------------------------------------- */
typedef enum MDS_BOOT_Result {
    MDS_BOOT_RESULT_NONE = 0x0000,
    MDS_BOOT_RESULT_SUCCESS = 0xE000,
    MDS_BOOT_RESULT_ECHECK,
    MDS_BOOT_RESULT_ERETRY,
    MDS_BOOT_RESULT_EIO,
    MDS_BOOT_RESULT_ENOMEM,
    MDS_BOOT_RESULT_ELZMA = 0xE200,
} MDS_BOOT_Result_t;

enum MDS_BOOT_FLAG {
    MDS_BOOT_FLAG_NONE = 0x0000,
    MDS_BOOT_FLAG_COPY = 0x0001,
    MDS_BOOT_FLAG_LZMA = 0x0020,
};

typedef struct MDS_BOOT_BinInfo {
    uint8_t check[sizeof(uint16_t)];
    uint8_t flag[sizeof(uint16_t)];
    uint8_t dstAddr[sizeof(uint32_t)];
    uint8_t srcSize[sizeof(uint32_t)];
    uint8_t hash[MDS_BOOT_CHKHASH_SIZE];

    // context of `uint8_t data[srcSize]` for upgrade bin
} MDS_BOOT_BinInfo_t;

typedef struct MDS_BOOT_UpgradeInfo {
    uint8_t check[sizeof(uint16_t)];  // check upgradeInfo header
    uint8_t magic[sizeof(uint16_t)];
    uint8_t type[sizeof(uint16_t)];   // type comfired for firmware
    uint8_t count[sizeof(uint16_t)];  // count of binInfos
    uint8_t size[sizeof(uint32_t)];   // totalSize
    uint8_t hash[MDS_BOOT_CHKHASH_SIZE];

    // context of `MDS_BOOT_BinInfo_t binInfo[count]` for upgrade bin combain
} MDS_BOOT_UpgradeInfo_t;

typedef struct MDS_BOOT_SwapInfo {
    uint16_t check;
    uint16_t magic;
    uint16_t type;
    uint16_t count;
    uint32_t size;
    uint8_t hash[MDS_BOOT_CHKHASH_SIZE];

    uint16_t retry;
    uint16_t version;
    uint32_t reset;
    uint32_t result;
} MDS_BOOT_SwapInfo_t;

typedef struct MDS_BOOT_UpgradeOps {
    MDS_Err_t (*read)(MDS_Arg_t *dev, intptr_t ofs, uint8_t *data, size_t len);
    MDS_Err_t (*write)(MDS_Arg_t *dev, intptr_t ofs, const uint8_t *data, size_t len);
    MDS_Err_t (*erase)(MDS_Arg_t *dev);
    bool (*compare)(const MDS_BOOT_UpgradeInfo_t *upgradeInfo);
} MDS_BOOT_UpgradeOps_t;

/* Function ---------------------------------------------------------------- */
extern MDS_Err_t MDS_BOOT_UpgradeRead(MDS_Arg_t *dev, intptr_t ofs, uint8_t *buff, size_t size);
extern MDS_Err_t MDS_BOOT_UpgradeWrite(MDS_Arg_t *dev, intptr_t ofs, const uint8_t *buff, size_t size);
extern MDS_Err_t MDS_BOOT_UpgradeErase(MDS_Arg_t *dev);

extern MDS_BOOT_Result_t MDS_BOOT_UpgradeCheck(MDS_BOOT_SwapInfo_t *swapInfo, MDS_Arg_t *dst, MDS_Arg_t *src,
                                               const MDS_BOOT_UpgradeOps_t *ops);
extern MDS_BOOT_SwapInfo_t *MDS_BOOT_GetSwapInfo(void);

extern MDS_BOOT_Result_t MDS_BOOT_UpgradeCopy(MDS_Arg_t *dst, MDS_Arg_t *src, size_t srcOfs,
                                              const MDS_BOOT_BinInfo_t *binInfo);
extern MDS_BOOT_Result_t MDS_BOOT_UpgradeLzma(MDS_Arg_t *dst, MDS_Arg_t *src, size_t srcOfs,
                                              const MDS_BOOT_BinInfo_t *binInfo);

#ifdef __cplusplus
}
#endif

#endif /* __MDS_BOOT_H__ */
