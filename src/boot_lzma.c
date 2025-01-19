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
/* Include ----------------------------------------------------------------- */
#include "mds_boot.h"
#include "mds_log.h"
#include "LzmaDec.h"

/* Define ------------------------------------------------------------------ */
#ifndef MDS_BOOT_LZMA_READ_SIZE
#define MDS_BOOT_LZMA_READ_SIZE 1024
#endif

#ifndef MDS_BOOT_LZMA_WRITE_SIZE
#define MDS_BOOT_LZMA_WRITE_SIZE 1024
#endif

#ifndef MDS_BOOT_LZMA_DICT_SIZE
#define MDS_BOOT_LZMA_DICT_SIZE 4096
#endif

#ifndef MDS_BOOT_LZMA_PROBS_SIZE
#define MDS_BOOT_LZMA_PROBS_SIZE 10112
#endif

#define BOOT_LZMA_HEADER_SIZE (LZMA_PROPS_SIZE + sizeof(uint64_t))
#define BOOT_LZMA_ALIGN_SIZE  sizeof(size_t)

/* Variable ---------------------------------------------------------------- */
static uint8_t g_lzmaReadBuff[VALUE_ALIGN(MDS_BOOT_LZMA_READ_SIZE + BOOT_LZMA_ALIGN_SIZE - 1, BOOT_LZMA_ALIGN_SIZE)];
static uint8_t g_lzmaWriteBuff[VALUE_ALIGN(MDS_BOOT_LZMA_WRITE_SIZE + BOOT_LZMA_ALIGN_SIZE - 1, BOOT_LZMA_ALIGN_SIZE)];

static struct BOOT_LzmaDict {
    bool used;
    uint8_t buff[MDS_BOOT_LZMA_DICT_SIZE];
} g_bootLzmaDict;

static struct BOOT_LzmaProbs {
    bool used;
    uint8_t buff[MDS_BOOT_LZMA_PROBS_SIZE];
} g_bootLzmaProbs;

static void *BOOT_LzmaAlloc(ISzAllocPtr p, size_t size)
{
    UNUSED(p);

    if ((size <= sizeof(g_bootLzmaProbs.buff)) && (!g_bootLzmaProbs.used)) {
        g_bootLzmaProbs.used = true;
        return (g_bootLzmaProbs.buff);
    }

    if ((size <= sizeof(g_bootLzmaDict.buff)) && (!g_bootLzmaDict.used)) {
        g_bootLzmaDict.used = true;
        return (g_bootLzmaDict.buff);
    }

    return (NULL);
}

static void BOOT_LzmaFree(ISzAllocPtr p, void *address)
{
    UNUSED(p);

    if (address == g_bootLzmaProbs.buff) {
        g_bootLzmaProbs.used = false;
    } else if (address == g_bootLzmaDict.buff) {
        g_bootLzmaDict.used = false;
    }
}

static const ISzAlloc G_LZMA_ALLOC = {BOOT_LzmaAlloc, BOOT_LzmaFree};

/* Function ---------------------------------------------------------------- */
static void BOOT_BuffMoveAligned(uint8_t *buff, size_t outPos, size_t wSize)
{
    for (size_t i = 0; i < outPos; i++) {
        buff[i] = buff[wSize + i];
    }
}

static MDS_BOOT_Result_t BOOT_LzmaDecodeUpgrade(CLzmaDec *dec, MDS_Arg_t *dst, MDS_Arg_t *src, size_t srcOfs,
                                                size_t srcSize, uint64_t unpackSize)
{
    bool thereIsSize = (unpackSize != __UINT64_MAX__);
    size_t inPos = 0, inSize = 0, outPos = 0, wSize = 0, wIndex = 0, rIndex = 0;

    for (size_t cnt = 0;; cnt++) {
        if (inPos == inSize) {
            inSize = ((srcSize - rIndex) > sizeof(g_lzmaReadBuff)) ? (sizeof(g_lzmaReadBuff)) : (srcSize - rIndex);
            if (MDS_BOOT_UpgradeRead(src, srcOfs + rIndex, g_lzmaReadBuff, inSize) != MDS_EOK) {
                return (MDS_BOOT_RESULT_EIO);
            }
            rIndex += inSize;
            inPos = 0;
        }

        size_t inProcessed = inSize - inPos, outProcessed = sizeof(g_lzmaWriteBuff) - outPos;
        MDS_LOG_D("[read] inSize:%u inPos:%u inProc:%u outPos:%u outProc:%u cnt:%u", inSize, inPos, inProcessed, inPos,
                  outProcessed, cnt);

        ELzmaFinishMode finishMode = LZMA_FINISH_ANY;
        if (thereIsSize && (outProcessed > unpackSize)) {
            outProcessed = (size_t)unpackSize;
            finishMode = LZMA_FINISH_END;
        }

        MDS_LOG_D("[decode] before inPos:%u rIndex:%u inProc:%u wIndex:%u, outPos:%u outProc:%u", inPos, rIndex,
                  inProcessed, wIndex, outPos, outProcessed);
        ELzmaStatus status;
        SRes res = LzmaDec_DecodeToBuf(dec, g_lzmaWriteBuff + outPos, &outProcessed, g_lzmaReadBuff + inPos,
                                       &inProcessed, finishMode, &status);
        MDS_LOG_D("[decode] after res:%u status:%u inProc:%u outProc:%u", res, status, inProcessed, outProcessed);
        if (res != SZ_OK) {
            return (MDS_BOOT_RESULT_ELZMA | (res & 0xFF));
        }

        inPos += inProcessed;
        outPos += outProcessed;
        unpackSize -= outProcessed;
        wSize = outPos - (outPos % BOOT_LZMA_ALIGN_SIZE);

        MDS_LOG_D("[write] inPos:%u outPos:%u wIndex:%u wSize:%u", inPos, outPos, wIndex, wSize);
        if (MDS_BOOT_UpgradeWrite(dst, wIndex, g_lzmaWriteBuff, wSize) != MDS_EOK) {
            return (MDS_BOOT_RESULT_EIO);
        }

        wIndex += wSize;
        outPos = outPos % BOOT_LZMA_ALIGN_SIZE;
        BOOT_BuffMoveAligned(g_lzmaWriteBuff, outPos, wSize);
        MDS_LOG_D("[loop] wIndex:%u outPos:%u thereIsSize:%u inProc:%u outProc:%u unpackSize:%llu", wIndex, outPos,
                  thereIsSize, inProcessed, outProcessed, unpackSize);

        if (thereIsSize && (unpackSize == 0)) {
            return (MDS_BOOT_RESULT_SUCCESS);
        } else if ((inProcessed == 0) && (outProcessed == 0)) {
            return ((thereIsSize || (status != LZMA_STATUS_FINISHED_WITH_MARK)) ? MDS_BOOT_RESULT_ELZMA
                                                                                : MDS_BOOT_RESULT_SUCCESS);
        }
    }
}

MDS_BOOT_Result_t MDS_BOOT_UpgradeLzma(MDS_Arg_t *dst, MDS_Arg_t *src, size_t srcOfs, const MDS_BOOT_BinInfo_t *binInfo)
{
    uint8_t header[BOOT_LZMA_HEADER_SIZE];
    uint64_t unpackSize = 0;
    CLzmaDec dec;

    MDS_Err_t err = MDS_BOOT_UpgradeRead(src, srcOfs + sizeof(*binInfo), header, sizeof(header));
    if (err != MDS_EOK) {
        return (MDS_BOOT_RESULT_EIO);
    }

    for (uint8_t i = 0; i < (BOOT_LZMA_HEADER_SIZE - LZMA_PROPS_SIZE); i++) {
        unpackSize += ((uint64_t)header[LZMA_PROPS_SIZE + i]) << (i * MDS_BITS_OF_BYTE);
    }

    LzmaDec_Construct(&dec);
    if (LzmaDec_Allocate(&dec, header, LZMA_PROPS_SIZE, &G_LZMA_ALLOC) != SZ_OK) {
        return (MDS_BOOT_RESULT_ENOMEM);
    }

    err = MDS_BOOT_UpgradeErase(dst);
    if (err != MDS_EOK) {
        return (MDS_BOOT_RESULT_EIO);
    }

    LzmaDec_Init(&dec);
    MDS_BOOT_Result_t result = BOOT_LzmaDecodeUpgrade(&dec, dst, src, srcOfs + sizeof(*binInfo) + sizeof(header),
                                                      ALGO_GetU32BE(binInfo->srcSize), unpackSize);
    LzmaDec_Free(&dec, &G_LZMA_ALLOC);

    return (result);
}
