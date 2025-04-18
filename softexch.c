/*
 *  SM2 密钥交换 基于GmSSLv3实现
 *  author: zack
 *  email: cengxk@chinatelecom.cn
 * 本文件包含核心的 SM2 密钥交换协议函数：
 *  - sm2_z256_custom_operation：计算 x' = 2^w + (x & (2^w - 1))
 *  - sm2_compute_agree_point：派生共享椭圆曲线点 U
 *  - sm2_compute_key：通过 SM3-KDF 导出对称密钥并生成确认摘要 S1, S2
 */
#include "softexch.h"
#include <gmssl/mem.h>
#include <gmssl/sm3.h>
#include <stdint.h>
#include <string.h>
#define GM_SM2_W 127 // SM2 截断操作的比特宽度参数

static void print_hex(const char *label, const unsigned char *buf, size_t len)
{
    printf("%-8s: ", label);
    for (size_t i = 0; i < len; i++)
    {
        printf("%02X", buf[i]);
    }
    printf("\n");
}
#define GM_SM2_W 127 // SM2 截断操作的比特宽度参数

/**
 * @brief  对 256 位大整数 x 执行截断运算：
 *         x = 2^w + (x & (2^w - 1))
 * @param  x  4×64 位小端数组，输入输出参数
 * @param  w  截断比特索引 (0 <= w < 256)
 */
static inline void sm2_z256_custom_operation(sm2_z256_t x, unsigned int w)
{
    // 1. 构造掩码 mask = (2^w) - 1
    sm2_z256_t mask = {0};
    unsigned int full_words = w / 64; // 完整 64 位字数
    unsigned int rem_bits = w % 64;   // 剩余位数
    for (unsigned int i = 0; i < full_words && i < 4; i++)
    {
        mask[i] = UINT64_MAX;
    }
    if (full_words < 4 && rem_bits)
    {
        mask[full_words] = ((uint64_t)1 << rem_bits) - 1;
    }

    // 2. 计算 two_pow = 2^w
    sm2_z256_t two_pow = {0};
    if (w < 256)
    {
        two_pow[w / 64] = (uint64_t)1 << (w % 64);
    }

    // 3. 就地更新 x = two_pow + (x & mask)
    for (int i = 0; i < 4; i++)
    {
        x[i] = two_pow[i] + (x[i] & mask[i]);
    }
}

/**
 * @brief  计算共享椭圆曲线点 U = [t](P + [h]R)
 * @param  U              输出的共享点
 * @param  own_static     本地静态密钥对
 * @param  own_ephemeral  本地临时密钥对
 * @param  peer_static    对端静态公钥
 * @param  peer_ephemeral 对端临时公钥
 * @return 成功返回 1，错误返回 -1
 */
int sm2_compute_agree_point(SM2_Z256_POINT *U, const SM2_KEY *own_static, const SM2_KEY *own_ephemeral,
                            const SM2_POINT *peer_static, const SM2_POINT *peer_ephemeral)
{
    SM2_Z256_POINT P, R, hR, P_plus_hR;
    sm2_z256_t r, d, x1, h1, t;

    // 1) 反序列化对端静态和临时公钥
    if (!sm2_z256_point_from_bytes(&P, (uint8_t *)peer_static) ||
        !sm2_z256_point_from_bytes(&R, (uint8_t *)peer_ephemeral))
    {
        return -1;
    }

    // 2) 拷贝本地私钥到局部变量
    memcpy(r, own_ephemeral->private_key, sizeof(r));
    memcpy(d, own_static->private_key, sizeof(d));

    // 3) 提取本地临时公钥 x 坐标并执行截断 x1'
    if (sm2_z256_point_get_xy(&own_ephemeral->public_key, x1, NULL) < 0)
    {
        return -1;
    }
    sm2_z256_custom_operation(x1, GM_SM2_W);

    // 4) 加载对端临时公钥 x 坐标并截断 h1'
    sm2_z256_from_bytes(h1, peer_ephemeral->x);
    sm2_z256_custom_operation(h1, GM_SM2_W);

    // 5) 计算中间点：hR = [h1']R, P_plus_hR = P + hR
    sm2_z256_point_mul(&hR, h1, &R);
    sm2_z256_point_add(&P_plus_hR, &P, &hR);

    // 6) 计算 t = (d + x1' * r) mod n
    sm2_z256_modn_mul(t, x1, r);
    sm2_z256_modn_add(t, d, t);

    // 7) 计算共享点 U = [t](P_plus_hR)
    sm2_z256_point_mul(U, t, &P_plus_hR);

    // 8) 验证 U 是否在曲线上
    if (!sm2_z256_point_is_on_curve(U))
    {
        return -1;
    }
    return 1;
}

/**
 * @brief  SM2 密钥交换主函数：导出对称密钥并生成确认摘要 S1/S2
 * @param  kbuf              输出共享对称密钥缓冲区
 * @param  klen              密钥长度 (字节)
 * @param  own_static        本地静态密钥对
 * @param  own_ephemeral     本地临时密钥对
 * @param  peer_static_puk   对端静态公钥
 * @param  peer_ephemeral_puk对端临时公钥
 * @param  own_id            本地用户标识
 * @param  own_id_len        标识长度
 * @param  peer_id           对端用户标识
 * @param  peer_id_len       标识长度
 * @param  isInitiator       标志：1 表示发起方，0 表示响应方
 * @return 成功返回 1，失败返回 -1
 */
int sm2_compute_key(uint8_t *kbuf, unsigned int klen, const SM2_KEY *own_static, const SM2_KEY *own_ephemeral,
                    const SM2_POINT *peer_static_puk, const SM2_POINT *peer_ephemeral_puk, const unsigned char *own_id,
                    unsigned int own_id_len, const unsigned char *peer_id, unsigned int peer_id_len,
                    unsigned char isInitiator)
{
    SM2_Z256_POINT pub_peer, U;
    uint8_t ZA[32], ZB[32], xy_buf[64];
    SM3_KDF_CTX kdf;

    // 1) 反序列化对端静态公钥
    if (!sm2_z256_point_from_bytes(&pub_peer, (uint8_t *)peer_static_puk))
    {
        return -1;
    }

    // 2) 计算用户标识哈希 ZA, ZB
    if (!sm2_compute_z(ZA, &own_static->public_key, (char *)own_id, own_id_len) ||
        !sm2_compute_z(ZB, &pub_peer, (char *)peer_id, peer_id_len))
    {
        return -1;
    }

    // 3) 计算共享椭圆曲线点 U
    if (!sm2_compute_agree_point(&U, own_static, own_ephemeral, peer_static_puk, peer_ephemeral_puk))
    {
        return -1;
    }

    // 4) 序列化 U.x||U.y
    sm2_z256_point_to_bytes(&U, xy_buf);

    // 5) SM3-KDF：输入 xy_buf||ZA||ZB（顺序由发起者标志决定）
    sm3_kdf_init(&kdf, klen);
    sm3_kdf_update(&kdf, xy_buf, 64);
    if (isInitiator)
    {
        sm3_kdf_update(&kdf, ZA, 32);
        sm3_kdf_update(&kdf, ZB, 32);
    }
    else
    {
        sm3_kdf_update(&kdf, ZB, 32);
        sm3_kdf_update(&kdf, ZA, 32);
    }
    sm3_kdf_finish(&kdf, kbuf);
    // print_hex("compute key", kbuf, klen);

    // 6) (可选)生成并打印确认摘要 S1, S2
    {
        uint8_t inner[32], S1[32], S2[32];
        SM3_CTX ctx;
        SM2_Z256_POINT peer_eph_point;
        uint8_t eph1[64], eph2[64];

        // 序列化本地临时公钥 eph1
        sm2_z256_point_to_bytes(&own_ephemeral->public_key, eph1);
        // 反序列化并序列化对端临时公钥 eph2
        if (!sm2_z256_point_from_bytes(&peer_eph_point, (uint8_t *)peer_ephemeral_puk))
        {
            return -1;
        }
        sm2_z256_point_to_bytes(&peer_eph_point, eph2);

        // 6.1 计算内层哈希：inner = Hash(xU||yU||ZA||ZB||eph1||eph2)
        sm3_init(&ctx);
        sm3_update(&ctx, xy_buf, 32);
        if (isInitiator)
        {
            sm3_update(&ctx, ZA, 32);
            // print_hex("ZA", ZA, 32);
            sm3_update(&ctx, ZB, 32);
            // print_hex("ZB", ZB, 32);
            sm3_update(&ctx, eph1, 64);
            // print_hex("eph1", eph1, 64);
            sm3_update(&ctx, eph2, 64);
            // print_hex("eph2", eph2, 64);
        }
        else
        {
            sm3_update(&ctx, ZB, 32);
            sm3_update(&ctx, ZA, 32);
            sm3_update(&ctx, eph2, 64);
            sm3_update(&ctx, eph1, 64);
        }

        sm3_finish(&ctx, inner);

        // 6.2 计算 S1 = Hash(0x02||yU||inner)
        uint8_t tag = 0x02;
        sm3_init(&ctx);
        sm3_update(&ctx, &tag, 1);
        sm3_update(&ctx, xy_buf + 32, 32);
        sm3_update(&ctx, inner, 32);
        sm3_finish(&ctx, S1);
        print_hex("S1", S1, 32);

        // 6.3 计算 S2 = Hash(0x03||yU||inner)
        tag = 0x03;
        sm3_init(&ctx);
        sm3_update(&ctx, &tag, 1);
        sm3_update(&ctx, xy_buf + 32, 32);
        sm3_update(&ctx, inner, 32);
        sm3_finish(&ctx, S2);
        print_hex("S2", S2, 32);
    }

    // 清理kdf上下文
    gmssl_secure_clear(&kdf, sizeof(kdf));
    return 1;
}
