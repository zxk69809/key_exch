#ifndef HEADER_EXCH_H
#define HEADER_EXCH_H

#include <gmssl/sm2.h>
#include <stdio.h>

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
                    unsigned char isInitiator);
#endif
