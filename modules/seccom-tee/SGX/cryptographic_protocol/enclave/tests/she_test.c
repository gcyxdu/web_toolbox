#include "she.h"
// #include "../TestEnclave.h"
#define TEST_TIMES 10000
extern SHE_key KEY;

// void bn_printfHex(BIGNUM *num)
// {
//         char *tmp = BN_bn2hex(num);
//         printf("%s\n", tmp);
//         OPENSSL_free(tmp);
// }

// void bn_printfDec(BIGNUM *num)
// {
//         char *tmp = BN_bn2dec(num);
//         printf("%s\n", tmp);
//         OPENSSL_free(tmp);
// }


int she_functionTest()
{
        int ret = 0;
        SHE_key key;

        BN_CTX *ctx = BN_CTX_new();
        BN_CTX_start(ctx);

        int space_num;
        char *tmp1, *tmp2;
        BIGNUM *random_plain1 = BN_CTX_get(ctx);
        BIGNUM *random_plain2 = BN_CTX_get(ctx);
        BIGNUM *cipher1 = BN_CTX_get(ctx);
        // BIGNUM *cipher2 = BN_CTX_get(ctx);
        char *plain_str;
        BIGNUM *decrypted_random = BN_CTX_get(ctx);
        // BIGNUM *tmp_result1 = BN_CTX_get(ctx);
        // BIGNUM *tmp_result2 = BN_CTX_get(ctx);

        if (!BN_rand(random_plain1, DEFAULT_K1, 0, 0))
                goto end;
        if (!BN_rand(random_plain2, DEFAULT_K1, 0, 0))
                goto end;

        if (!she_generateRandomKeys(&key, DEFAULT_K0, DEFAULT_K1, DEFAULT_K2, ctx))
                goto end;
        // printf("SHE_KEY:p,q,l,n\n");
        // bn_printfHex(key.p);
        // bn_printfHex(key.q);
        // bn_printfHex(key.l);
        // bn_printfHex(key.n);

        she_encryptBignumSupportNegative(cipher1, random_plain1, &key, ctx);
        she_decryptBignum(decrypted_random, cipher1, &key, ctx);
        printf("Random plain number: ");
        bn_printfHex(random_plain1);
        printf("Decryted number:");
        bn_printfHex(decrypted_random);
        if (BN_cmp(decrypted_random, random_plain1) == 0)
        {
                printf("Bignum Interface Encryption and Decrytpion OK!\n");
        }
        else
        {
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
        if (space_num <= strlen(tmp2)) // 解密出来是明文，这个长度比密文小很多
                printf("space is not enough\n");
        // printf("len :%d\n",strlen(tmp2));
        printf("Plain: ");
        printf("%s\n", plain_str);
        printf("Decrypted: ");
        printf("%s\n", tmp2);
        if (memcmp(tmp2, plain_str, strlen(plain_str)) == 0)
        {
                printf("EncrytTeeString and DecryptTeeString OK!\n");
        }
        else
        {
                printf("EncrytTeeString and DecryptTeeString Error!\n");
        }

        ///////////// Addition test 同态加正确性测试
        // E(m1)+E(m2) = E(m1+m2)
        if (!she_addTest(&key, ctx))
                goto end;
        ///////////// Multiplication test 同态乘法正确性测试
        // E(m1)*E(m2) = E(m1*m2)
        if (!she_mulTest(&key, ctx))
                goto end;
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        ret = 1;
end:
        if (!ret)
        {
                printf("FunctionTest Error\n");
        }
        return ret;
}

// int she_efficiencyTest()
// {
//         int ret = 0;
//         SHE_key key;

//         BN_CTX *ctx = BN_CTX_new();
//         BN_CTX_start(ctx);

//         int space_num;
//         char *tmp1, *tmp2;
//         BIGNUM *random_plain1 = BN_CTX_get(ctx);
//         BIGNUM *random_plain2 = BN_CTX_get(ctx);
//         BIGNUM *cipher1 = BN_CTX_get(ctx);
//         BIGNUM *cipher2 = BN_CTX_get(ctx);
//         char *plain_str;
//         BIGNUM *decrypted_random = BN_CTX_get(ctx);
//         BIGNUM *tmp_result1 = BN_CTX_get(ctx);
//         BIGNUM *tmp_result2 = BN_CTX_get(ctx);
//         if (!BN_rand(random_plain1, DEFAULT_K1, 0, 0))
//                 goto end;
//         if (!BN_rand(random_plain2, DEFAULT_K1, 0, 0))
//                 goto end;

//         if (!she_generateRandomKeys(&key, DEFAULT_K0, DEFAULT_K1, DEFAULT_K2, ctx))
//                 goto end;
//         // printf("SHE_KEY:p,q,l\n");
//         // bn_printfHex(key.p);
//         // bn_printfHex(key.q);
//         // bn_printfHex(key.l);
//         // bn_printfHex(key.n);

//         she_encryptBignumSupportNegative(cipher1, random_plain1, &key, ctx);
//         she_decryptBignum(decrypted_random, cipher1, &key, ctx);

//         space_num = 1025;
//         she_generateRandomKeysTee();
//         tmp1 = (char *)malloc(sizeof(char) * space_num);
//         tmp2 = (char *)malloc(sizeof(char) * space_num);
//         plain_str = (char *)malloc(sizeof(char) * space_num);
//         memcpy(plain_str, "AA", 3);
//         ///////////// Encryption and Decryption test
//         printf("%d times encryption\n", TEST_TIMES);
//         timeStart();
//         for (int i = 0; i < TEST_TIMES; i++)
//         {
//                 // if (encrypt_she(cipher1, random_plain1, &key, ctx) != 0)
//                 if (!she_encryptTeeString(tmp1, plain_str))
//                         goto end;
//         }
//         timeEnd("encryptTeeString uses time");
//         // printf("len :%d\n",strlen(tmp1));

//         printf("%d times decryption \n", TEST_TIMES);
//         timeStart();
//         for (int i = 0; i < TEST_TIMES; i++)
//         {
//                 if (!she_decryptTeeString(tmp2, tmp1))
//                         goto end;
//         }
//         timeEnd("decryptTeeString uses time");

//         // 同态密文加法测试用时
//         if (!she_encryptBignumSupportNegative(cipher2, random_plain2, &key, ctx))
//                 goto end;
//         printf("%d次addString\n", TEST_TIMES);
//         timeStart();
//         for (int i = 0; i < TEST_TIMES; i++)
//         {
//                 if (!addString(tmp1, tmp1, tmp1))
//                         goto end;
//         }
//         timeEnd();
//         if (space_num <= strlen(tmp2))
//                 printf("space is not enough\n");

//         // 同态密文乘法测试用时
//         printf("%d次mulString\n", TEST_TIMES);
//         timeStart();
//         for (int i = 0; i < TEST_TIMES; i++)
//         {
//                 // if (!BN_mod_mul(tmp_result1, cipher1, cipher2, key.n, ctx))
//                 if (!mulString(tmp1, tmp1, tmp2))
//                         goto end;
//         }
//         gettimeofday(&timeend, NULL);
//         timeuse = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
//         printf("%d times cypher multiplication uses time:%f s\n", TEST_TIMES, timeuse / 1000000);
//         if (space_num <= strlen(tmp2))
//                 printf("space is not enough\n");

//         BN_CTX_end(ctx);
//         BN_CTX_free(ctx);
//         ret = 1;
// end:
//         if (!ret)
//         {
//                 printf("EfficiencyTest Error\n");
//         }
//         return ret;
// }

int she_test()
{
        int ret = 0;
        if (!she_functionTest())
                goto END_LABEL;
        // if (!she_efficiencyTest())
        //         goto END_LABEL;
        ret = 1;
END_LABEL:
        if (!ret)
        {
                printf("sheTest Error\n");
        }
        return 1;
}

// int main()
// {
//         // she_test();
//         BN_CTX *ctx = BN_CTX_new();
//         BN_CTX_start(ctx);
//         BIGNUM *tmp1, *tmp2, *k_times;
//         tmp1 = BN_CTX_get(ctx);
//         tmp2 = BN_CTX_get(ctx);
//         k_times = BN_CTX_get(ctx);
//         // unsigned char *test1 = (unsigned char *)malloc(sizeof(char)*4);
//         int test1;
//         BN_set_word(k_times, 1000);
//         BN_bn2lebinpad(k_times,(unsigned char*)(&test1),4);

//         printf("test:%d\n",test1);
//         BN_CTX_end(ctx);
//         BN_CTX_free(ctx);
//         return 0;
// }

// fengwei master propose the relu scheme
int ecall_decrypt_relu_signal(char *str_plain, char *str_c)
{
        // char *e0 = "1F8271F1467B07EF9B0D3C7DDE86ACD9A17E5A123533AD202B612D4EE014B15A22661CE8D1BFC412F367C513BA6380255B920411E4A3B8C87F21A9554EF526CC746536B21ECD9E1A34D4D21F28E29448CAB397CCD78DF858F8D8158709880F414FAAC6019B27075D79F81BE337E1808DDA19333A800AEFBF3515D32AB8E502C82F9ABE89FDDDF752E67B28E4A4D4AF58E33056786DCD59667CDCDDEA47C3D02518C24BC365368D560B9D130F22131AD6F80318892D5DE8A45E8093D95606C5B81BBA8B58BBE5FBCE5C199680FD12504C7ED0E695A9D18543538A8287CA4F0FE5D2B5074B4B64472931BCA641704C2DA22B2CBE61A416BE542B86E96EC7CFF25F48108FC6D077FEA2F2A374B68CB23B787B3A4BF5B2C1D4CEA964099ACB5CC47ABBE086F04382A0B6996F99E5FB6288082BAD7217B718B460CBE33A7C7ACAEC905100B2E1BA9EA9DD452ADE2C5C689147BB9A452159E2F89C5C78B24FE3B1B9DCF2262B9640815634296D98FBAC0FDA4EEAF0592BEE37394E65170AC174B700A198DC52115365AD9DA329DF12A69D6025A8353386A43B94415D59D282C3324DA6F9007C059681EEBD043E3356A068D276E7F8CED7D0E73853745027EBD47D0293F0D44AFEF34F22317CF0B966E9008AB7D234EC4463009A503882EF6996D310E5D58BA85B64A5B426B1AB1AF5E16974D1E6E45F04D4BB73C995E8F92D871DFC92";
        // char *e1 = "565A7918B92AE411861761592B0C075B341580BA15815F1E3C35039C9DEF132D53B13DE877129C3BA7667D43AE35A852923C1BCC015885CEBECE43CCB88F1CF7883F460AA1D1509038D9434262B5CF7DFE050BE236A5760ED9663472B29F3D97059D0C3F7E7141C15AE86D855743B1136EE01EFA82A5332B3006F03DD2EFF52A80E70E14644BC4E6E8829CEA5303BA0487AFBD988C253C674C493F4923175FEB29DD1CCD8E0656F176DD816A3BA60508257319CFC36B78965B2F8A31ADA7845717212FED274F5E33E57F23CE5F93142CA2B2A0DE4F6B5DE263543907D7B90FED1D19BC789D3FFDE8131A10E054E759009DD7CDAB57BBF8F7AA1F5B6A43AA4428C287FED7892E63697439D790BE030B4835A90A858D12D272327F87C74BDA851BB1B07C5E105B41DCFB7ED6E8F45F0CD7ADCCC022FC62DFC0BA7777016314D754CF96A6FED5E3C6177C22E4AE6155D883E5572EDD62284449C4F094746D6B0E6B67308D223BAACC0FA9A9C64D89D6AB9466EC6E9F0A6EC930B9B83A7D57038C925311CCA2102B7939638984C85E23C3E08840000BB73B146D2F098E7355C2D247029F79AAA5D1C3E37BED5F9224A04C620CC954A41AD22870297A529277F8655A4A6659E037C56C45475BC6BC7249B8A47A1C9928CC714FB8010B090C1B2C2499033F5F4C18A5D6F7586F1682D1261BAF62BCB36B4C60D900E3F2614D49E93B38";
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
        // BIGNUM *tmp_plain = BN_CTX_get(ctx);
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
        if (BN_cmp(l_2, plain) == -1)
        {
                BN_sub(plain, plain, KEY.l);
        }

        // printf("中见：\n");
        // BN_printf_she(plain);

        if (BN_cmp(plain, tmp_3) == -1)
                BN_zero(tmp_cipher);
        else
        {
                BN_set_word(tmp_cipher, 1);
        }
        // BN_div(tmp_plain, NULL, plain, k_times, ctx);
        // encrypt_she(tmp_cipher, tmp_plain, &KEY, ctx);

        char *tmp_ = BN_bn2hex(tmp_cipher);
        memcpy(str_plain, tmp_, strlen(tmp_) + 1);
        strlen1 = strlen(str_plain);
        memcpy(str_plain + strlen1, demi, 2);
        for (i = 1; i < 256; i++)
        {
                p_ = strtok(NULL, demi);
                BN_hex2bn(&c, p_);
                if (!BN_mod(tmp, c, KEY.p, ctx))
                        goto end;
                if (!BN_mod(plain, tmp, KEY.l, ctx))
                        goto end;
                if (BN_cmp(l_2, plain) == -1)
                {
                        BN_sub(plain, plain, KEY.l);
                }

                // if (BN_cmp(plain, tmp_3) == -1)
                //         BN_zero(plain);
                // BN_div(tmp_plain, NULL, plain, k_times, ctx);
                // encrypt_she(tmp_cipher, tmp_plain, &KEY, ctx);
                if (BN_cmp(plain, tmp_3) == -1)
                        BN_zero(tmp_cipher);
                else
                {
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
        if (ret)
        {
                printf("error\n");
        }
        BN_CTX_end(ctx);
        return ret;
}
