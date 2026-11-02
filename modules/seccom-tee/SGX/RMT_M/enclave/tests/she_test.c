#include "she.h"

#define TEST_TIMES 10000
extern SHE_key KEY;

int she_functionTest() {
    int ret = 0;
    SHE_key key;

    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    int space_num;
    char *tmp1, *tmp2;
    BIGNUM *random_plain1 = BN_CTX_get(ctx);
    BIGNUM *random_plain2 = BN_CTX_get(ctx);
    BIGNUM *cipher1 = BN_CTX_get(ctx);

    char *plain_str;
    BIGNUM *decrypted_random = BN_CTX_get(ctx);

    if (!BN_rand(random_plain1, DEFAULT_K1, 0, 0))
        goto end;
    if (!BN_rand(random_plain2, DEFAULT_K1, 0, 0))
        goto end;

    if (!she_generateRandomKeys(&key, DEFAULT_K0, DEFAULT_K1, DEFAULT_K2, ctx))
        goto end;

    she_encryptBignumSupportNegative(cipher1, random_plain1, &key, ctx);
    she_decryptBignum(decrypted_random, cipher1, &key, ctx);
    printf("Random plain number: ");
    bn_printfHex(random_plain1);
    printf("Decryted number:");
    bn_printfHex(decrypted_random);
    if (BN_cmp(decrypted_random, random_plain1) == 0) {
        printf("Bignum Interface Encryption and Decrytpion OK!\n");
    } else {
        printf("Bignum Interface Encryption and Decrytpion Error!\n");
    }

    space_num = 1025;
    she_generateRandomKeysTee();
    tmp1 = (char *)malloc(sizeof(char) * space_num);
    tmp2 = (char *)malloc(sizeof(char) * space_num);
    plain_str = (char *)malloc(sizeof(char) * space_num);
    memcpy(plain_str, "AA", 3);

    if (!she_encryptTeeString(tmp1, plain_str))
        goto end;
    if (space_num <= strlen(tmp1))
        printf("space is not enough\n");
    if (!she_decryptTeeString(tmp2, tmp1))
        goto end;
    if (space_num <= strlen(tmp2))
        printf("space is not enough\n");

    printf("Plain: ");
    printf("%s\n", plain_str);
    printf("Decrypted: ");
    printf("%s\n", tmp2);
    if (memcmp(tmp2, plain_str, strlen(plain_str)) == 0) {
        printf("EncrytTeeString and DecryptTeeString OK!\n");
    } else {
        printf("EncrytTeeString and DecryptTeeString Error!\n");
    }

    if (!she_addTest(&key, ctx))
        goto end;

    if (!she_mulTest(&key, ctx))
        goto end;
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    ret = 1;
end:
    if (!ret) {
        printf("FunctionTest Error\n");
    }
    return ret;
}

int she_test() {
    int ret = 0;
    if (!she_functionTest())
        goto END_LABEL;

    ret = 1;
END_LABEL:
    if (!ret) {
        printf("sheTest Error\n");
    }
    return 1;
}

int ecall_decrypt_relu_signal(char *str_plain, char *str_c) {
    int ret = 1;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *tmp = BN_CTX_get(ctx);
    BIGNUM *plain = BN_CTX_get(ctx);
    BIGNUM *c = BN_CTX_get(ctx);
    BIGNUM *tmp_2 = BN_CTX_get(ctx);
    BIGNUM *l_2 = BN_CTX_get(ctx);
    BIGNUM *tmp_3 = BN_CTX_get(ctx);
    BIGNUM *k_times = BN_CTX_get(ctx);

    BIGNUM *tmp_cipher = BN_CTX_get(ctx);

    BN_set_word(k_times, 1000);
    BN_zero(tmp_3);
    int strlen1, strlen2, i;
    char *p_ = NULL;
    char *demi = ";";
    p_ = strtok(str_c, demi);
    BN_hex2bn(&c, p_);
    BN_set_word(tmp_2, 2);
    if (!BN_mod(tmp, c, KEY.p, ctx))
        goto end;
    if (!BN_mod(plain, tmp, KEY.l, ctx))
        goto end;
    if (!BN_div(l_2, NULL, KEY.l, tmp_2, ctx))
        goto end;
    if (BN_cmp(l_2, plain) == -1) {
        BN_sub(plain, plain, KEY.l);
    }

    if (BN_cmp(plain, tmp_3) == -1)
        BN_zero(tmp_cipher);
    else {
        BN_set_word(tmp_cipher, 1);
    }

    char *tmp_ = BN_bn2hex(tmp_cipher);
    memcpy(str_plain, tmp_, strlen(tmp_) + 1);
    strlen1 = strlen(str_plain);
    memcpy(str_plain + strlen1, demi, 2);
    for (i = 1; i < 256; i++) {
        p_ = strtok(NULL, demi);
        BN_hex2bn(&c, p_);
        if (!BN_mod(tmp, c, KEY.p, ctx))
            goto end;
        if (!BN_mod(plain, tmp, KEY.l, ctx))
            goto end;
        if (BN_cmp(l_2, plain) == -1) {
            BN_sub(plain, plain, KEY.l);
        }

        if (BN_cmp(plain, tmp_3) == -1)
            BN_zero(tmp_cipher);
        else {
            BN_set_word(tmp_cipher, 1);
        }

        tmp_ = BN_bn2hex(tmp_cipher);
        strlen1 = strlen(str_plain);
        strlen2 = strlen(tmp_);
        memcpy(str_plain + strlen1, tmp_, strlen2 + 1);
        if (i != 255)
            memcpy(str_plain + strlen1 + strlen2, demi, 2);
    }

    ret = 0;
end:
    if (ret) {
        printf("error\n");
    }
    BN_CTX_end(ctx);
    return ret;
}
