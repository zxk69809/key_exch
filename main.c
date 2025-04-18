/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <gmssl/sm3.h>
#include "softexch.h"
#include <assert.h>
#include <gmssl/error.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4_cbc_mac.h>
// 错误处理函数
void handle_error(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}
static void print_hex(const char *label, const unsigned char *buf, size_t len)
{
    printf("%-8s: ", label);
    for (size_t i = 0; i < len; i++)
    {
        printf("%02X", buf[i]);
    }
    printf("\n");
}

int test_exch()
{

    const char *user_a_id_str = "1234567812345678";
    const char *user_a_private_key_str = "81EB26E941BB5AF16DF116495F90695272AE2CD63D6C4AE1678418BE48230029";
    const char *user_a_public_key_str = "160E12897DF4EDB61DD812FEB96748FBD3CCF4FFE26AA6F6DB9540AF49C94232"
                                        "4A7DAD08BB9A459531694BEB20AA489D6649975E1BFCF8C4741B78B4B223007F";

    const char *user_a_temp_private_key_str = "D4DE15474DB74D06491C440D305E012400990F3E390C7E87153C12DB2EA60BB3";
    const char *user_a_temp_public_key_str = "64CED1BDBC99D590049B434D0FD73428CF608A5DB8FE5CE07F15026940BAE40E"
                                             "376629C7AB21E7DB260922499DDB118F07CE8EAAE3E7720AFEF6A5CC062070C0";

    // 用户 B 的信息
    const char *user_b_id_str = "1234567812345678";
    const char *user_b_private_key_str = "785129917D45A9EA5437A59356B82338EAADDA6CEB199088F14AE10DEFA229B5";
    const char *user_b_public_key_str = "6AE848C57C53C7B1B5FA99EB2286AF078BA64C64591B8B566F7357D576F16DFB"
                                        "EE489D771621A27B36C5C7992062E9CD09A9264386F3FBEA54DFF69305621C4D";
    const char *user_b_temp_private_key_str = "7E07124814B309489125EAED101113164EBF0F3458C5BD88335C1F9D596243D6";
    const char *user_b_temp_public_key_str = "ACC27688A6F7B706098BC91FF3AD1BFF7DC2802CDB14CCCCDB0A90471F9BD707"
                                             "2FEDAC0494B2FFC4D6853876C79B8F301C6573AD0AA50F39FC87181E1A1B46FE";
    const char *shared_key_str = "6C89347354DE2484C60B4AB1FDE4C6E5";

    // 转换为字节数组
    uint8_t expected_shared_key[16];

    // 初始化 SM2_KEY 和 SM2_POINT 结构
    SM2_KEY user_a_static_key;
    SM2_KEY user_a_ephemeral_key;

    SM2_KEY user_b_static_key;
    SM2_KEY user_b_ephemeral_key;

    sm2_z256_t private_key_tmp;
    SM2_Z256_POINT public_key_tmp;
    // 设置用户 A 的静态密钥
    sm2_z256_from_hex(private_key_tmp, user_a_private_key_str);
    sm2_z256_point_from_hex(&public_key_tmp, user_a_public_key_str);
    sm2_key_set_public_key(&user_a_static_key, &public_key_tmp);
    sm2_key_set_private_key(&user_a_static_key, private_key_tmp);

    // 设置用户 A 的临时密钥
    sm2_z256_from_hex(private_key_tmp, user_a_temp_private_key_str);
    sm2_z256_point_from_hex(&public_key_tmp, user_a_public_key_str);
    sm2_key_set_public_key(&user_a_ephemeral_key, &public_key_tmp);
    sm2_key_set_private_key(&user_a_ephemeral_key, private_key_tmp);

    // 设置用户 B 的静态密钥
    sm2_z256_from_hex(private_key_tmp, user_b_private_key_str);
    sm2_z256_point_from_hex(&public_key_tmp, user_b_public_key_str);
    sm2_key_set_public_key(&user_b_static_key, &public_key_tmp);
    sm2_key_set_private_key(&user_b_static_key, private_key_tmp);

    // 设置用户 B 的临时密钥
    sm2_z256_from_hex(private_key_tmp, user_b_temp_private_key_str);
    sm2_z256_point_from_hex(&public_key_tmp, user_b_temp_public_key_str);
    sm2_key_set_public_key(&user_b_ephemeral_key, &public_key_tmp);
    sm2_key_set_private_key(&user_b_ephemeral_key, private_key_tmp);
    SM2_POINT peer_static_puk, peer_ephemeral_puk;

    sm2_z256_point_to_bytes(&user_b_static_key.public_key, &peer_static_puk);
    sm2_z256_point_to_bytes(&user_b_ephemeral_key.public_key, &peer_ephemeral_puk);

    uint8_t outbuf[32] = {0};
    if (!sm2_compute_key(outbuf, 16, &user_a_static_key, &user_a_ephemeral_key, &peer_static_puk, &peer_ephemeral_puk,
                         user_a_id_str, strlen(user_a_id_str), (const char *)user_b_id_str, strlen(user_a_id_str), 1))
    {
        error_print();
        return -1;
    }

    print_bytes(outbuf, 16);
    sm2_z256_point_to_bytes(&user_a_static_key.public_key, &peer_static_puk);
    sm2_z256_point_to_bytes(&user_a_ephemeral_key.public_key, &peer_ephemeral_puk);
    if (!sm2_compute_key(outbuf, 16, &user_b_static_key, &user_b_ephemeral_key, &peer_static_puk, &peer_ephemeral_puk,
                         user_b_id_str, strlen(user_b_id_str), (const char *)user_a_id_str, strlen(user_a_id_str), 0))
    {
        error_print();
        return -1;
    }
    print_bytes(outbuf, 16);
    return 1;
}

int main(void)
{
    test_exch();
    return 0;
}
