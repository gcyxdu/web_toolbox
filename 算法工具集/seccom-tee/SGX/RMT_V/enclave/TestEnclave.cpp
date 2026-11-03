/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>
#include <string.h>



#include "pthread.h"


#include "TestEnclave.h"
#include "TestEnclave_t.h"  /* print_string */
#include "tSgxSSL_api.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <vector>
#include "tests/random.h"
#include <cmath>

#include <stdlib.h>
#include <time.h>
#include <cstring>
#include <cstdio>


using namespace std;
using namespace seal;

const int thread_num=5;
const int len = 100000;
bool bit[len];
void* status;
BIGNUM* result[thread_num];




struct pvar
{
    int id;
    int start;
    int end;
    char** vector;
};


/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    uprint(buf);
}

void* partial_product(void* tpvar)
{
    
    
    struct pvar* in_pvar = (struct pvar*)tpvar;


    int id = in_pvar->id;
    int start = in_pvar->start;
    int end = in_pvar->end;
    char** vector = in_pvar->vector;

    // printf("%dbegin\n",id);


    BIGNUM* cipher;
    cipher = BN_new();
    BN_zero(cipher);
    BIGNUM* temp;
    temp = BN_new();
    for (int i = start; i < end; ++i)
    {
        
        // printf("%d\n",i);


        BN_hex2bn(&temp, *(vector+i));
        // printf("%s\n", BN_bn2hex(temp));
        if(bit[i]) BN_add(cipher, cipher, temp);
        // printf("%s\n", *(ptr+i));
        
    }
    BN_clear_free(temp);
    // printf("%s\n", BN_bn2hex(cipher));
    result[id] = cipher;

    // BN_CTX_end(ctx);
    // BN_CTX_free(ctx);

    // printf("%dend\n", id);
    return (void*) NULL;
}



void generate_bool()
{
    UniformRandomGenerator *ran = new StandardRandomAdapter<random_device>(0, 2);
    for (int i = 0; i < len; ++i)
    {
        int a = ran->generate();
        // printf("%d\n",a);
        if (a%2 == 1)
        {
            bit[i] = true;
        }else{
            bit[i] = true;
        }
    }

    // string key = "0123456789abcdef";


    unsigned char plaintext[] = "Hello, World!";
    unsigned char key[] = "0123456789ABCDEF0123456789ABCDEF";

    // 设置 AES 密钥长度（128 位）
    const int key_length = 128;

    // 分配加密和解密所需的缓冲区
    unsigned char ciphertext[sizeof(plaintext)];
    unsigned char decrypted[sizeof(plaintext)];

    // 创建 AES 加密和解密上下文
    AES_KEY aes_key;

    // 初始化 AES 密钥
    AES_set_encrypt_key(key, key_length, &aes_key);

    // 加密数据
    AES_encrypt(plaintext, ciphertext, &aes_key);

    // 打印加密后的结果
    printf("Ciphertext: %s\n", ciphertext);

    // 初始化 AES 密钥（用于解密）
    AES_set_decrypt_key(key, key_length, &aes_key);

    // 解密数据
    AES_decrypt(ciphertext, decrypted, &aes_key);

    // 打印解密后的结果
    printf("Decrypted text: %s\n", decrypted);
}




void test_ecall_inner_product(char** ptr, char* ret){

    

    generate_bool();

    printf("TEE multi-threads:\n%d\n", thread_num); 
    pthread_t threads[thread_num];
    int element_num = len / thread_num;


    BIGNUM* inner_product = BN_new();

    BN_zero(inner_product);



    for (int i=0; i<thread_num; ++i)
    {

        struct pvar tpvar;
        tpvar.id = i;
        tpvar.start = i*element_num;
        tpvar.end = (i+1)*element_num;
        if (i == thread_num-1)
        {
        tpvar.end = len;
        }
        tpvar.vector = ptr;
        int rc;
        rc = pthread_create(&threads[i], NULL, partial_product, (void*)&tpvar);
        if(rc){
            printf("Thread error.");
        }

    }


    
    for (int i=0; i<thread_num; ++i)
    {
        int rc;
        rc = pthread_join(threads[i], &status);
        if(rc){
                printf("Thread error.");
            }
        BN_add(inner_product, inner_product, result[i]);

        BN_clear_free(result[i]);
        
        
        // printf("%s\n", BN_bn2hex(result[i]));
    }

    char* s = BN_bn2hex(inner_product);
    memcpy(ret, s, strlen(s)+1);
    // printf("%s\n", s);

    // printf("%s\n", ret);

    // ret = BN_bn2hex(inner_product);

    pthread_exit(NULL);
    
}

//// 开始 操作 

AES_KEY aes_key;
int dim = 10; 
int dataBitLen = 4;
int partyNum = 10;

double *theta;
UniformRandomGenerator *ran = new StandardRandomAdapter<random_device>();


void initSystem(){
    unsigned char key[] = "0123456789ABCDEF0123456789ABCDEF";

    // 设置 AES 密钥长度（128 位）
    const int key_length = 128;

    // 初始化 AES 密钥
    AES_set_decrypt_key(key, key_length, &aes_key);

    theta = new double[dim * partyNum];
    // 初始化 theta 值
    for (int i = 0; i < dim * partyNum; ++i) {
        theta[i] = 0.5;
    }
}

string splitString(unsigned char* input, int blockIndex, int index){
    // 假设数据索引长度为3
    int local = index - blockIndex;
    string str = reinterpret_cast<const char*>(input);
    int len = dim*dataBitLen;
    return str.substr(3 + local*(dim*dataBitLen), dim*dataBitLen);
}

void extractData(string str, double* data){
    // 1000为放缩因子
    for (size_t i = 0; i < dim * partyNum; i++)
    {
        data[i] = stoi(str.substr(i*dataBitLen, dataBitLen)) / 1000.0;
    }

    // printf("input one participant's the first 10 data\n");
    for (size_t i = 0; i < 10; i++)
    {
        // printf("%lf ",data[i]);
    }
    // printf("\n\n");

    unsigned char plaintext[] = "001001900030018000400190003001800040019000300180004001900030018001900030018000400190003001800040019000300180004001900030018001900030018000400190003001800040019000300180004001900030018001900030018000400190003001800040019000300180004001900030018001900030018000400190003001800040019000300180004001900030018001900030018000400190003001800040019000300180004001900030018001900030018000400190003001800040019000300180004001900030018000300180004001900030018000400190003001800030018000400190003001800040019000300180012003000010019000300180004001900030018000400190003001800040019000300180019000300180004001900030018000400190003001800040019000300180019000300180004001900030018000400190003001800040019000300180019000300180004001900030018000400190003001800040019000300180019000300180004001900030018000400190003001800040019000300180019000300180004001900030018000400190003001800040019000300180019000300180004001900030018000400190003001800040019000300180003001800040019000300180004001900030018000300180004001900030018000400190003001800120030";

    // printf("input the block encrypted result for the partipant\n");
    // printf("%s\n\n",plaintext);
    

    // printf("Output the first 10 data\n");
    for (size_t i = 0; i < 10; i++)
    {
        // printf("%lf ",data[i]);
    }
    // printf("\n\n");
}

double sigmoid(double x) {
    return 1 / (1 + exp(-x));
}

void model_training(unsigned char* ciphertext, int length){
    double* theta_new = new double[dim * partyNum];
    // 初始化 theta 值
    for (int i = 0; i < dim * partyNum; ++i) {
        theta_new[i] = 0.0;
    }
    int p_is_check;
    // if(ran->generate() % 1000 > 500){
    //     p_is_check = ran->generate() % 1000;
    // }else{
    //     p_is_check = 200;
    // }
    p_is_check = ran->generate() % 1000;
    
    
    unsigned char ivec[] = "1234567890123456";
    unsigned char decrypted[length];
    

    // 1. 解密数据
    for (size_t i = 0; i < partyNum; i++)
    {
        AES_cbc_encrypt(ciphertext, decrypted, length, &aes_key, ivec, AES_DECRYPT);
    }

    // 2. 生成随机检验概率p
    int p_check = ran->generate() % 1000;
    // printf("%d\n", p_check);

    // 2.1 如果小于则进行检验
    if (p_check <= p_is_check){
        for (size_t i = 0; i < partyNum; i++)
        {
            string str = reinterpret_cast<const char*>(decrypted);
            string str1 = "001";
            if(str.substr(0,3).c_str() == str1){
                printf("success! success! success! success! success! success! \n");
            }else{
                // printf("fail! fail! fail! fail! fail! fail! \n");
            }
        }
    }

    // index 表示被随机选中的训练样本数目
    int index[] = {6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6};
    for (size_t n = 0; n < 1; n++)
    {
        // 3. 拼接所有参与方数据组成字符串
        string str;
        for (size_t i = 0; i < partyNum; i++)
        {
            str += splitString(decrypted, 3, index[n]).c_str();
        }

        // 4. 提取数据
        double data[dim * partyNum];
        extractData(str, data);
        
        // for (size_t i = 0; i < dim * partyNum; i++)
        // {
        //     printf("%f ", data[i]);
        // }
        // printf("\n");

        // 5. 计算预测值
        double y_predict = theta[0];
        for (size_t i = 1; i < dim * partyNum; i++)
        {
            y_predict += theta[i] * data[i-1]; 
        }

        // 6. 更新模型参数
        double temp = y_predict - data[dim * partyNum - 1];
        theta_new[0] += temp;
        for (size_t i = 1; i < dim * partyNum; i++)
        {
            theta_new[i] += temp * data[i-1];
            // printf("%f ", theta_new[i]);
        }
        // printf("\n");
    }
    

}

/* version 2.0 202408281336 */

// 随机数生成器，REE侧会调用
void Rand_Num_Generator(int* Rand_Num,int Lower,int Upper)
{
    // 初始化随机数种子，只需要调用一次
    
    // 生成[Lower, Upper]之间的随机整数
    *Rand_Num = Lower + ran->generate() % (Upper - Lower + 1);
}

// 块字符串解码，得到Xy_train，Validator为校验器。REE侧会调用
void decoding(float*** Xy_train_Output,char*** Block_Str,int* Participants,int Block_Size,int Num_Block,int Validator)
{
    int Number_Participants = 3; // 参与方个数为3
    int Num_Training_Samples = Num_Block * Block_Size; // 训练样本数

    // 计算总维度
    int Total_Dimensions = 0; // 初始化
    for(int i=0;i<Number_Participants;i++)
    {
        Total_Dimensions = Total_Dimensions + Participants[i];
    }

    // 动态分配二维整数数组Xy_train
    float** Xy_train = (float**)malloc(Num_Training_Samples * sizeof(float*));
    for(int i = 0;i < Num_Training_Samples;i++)
    {
        Xy_train[i] = (float*)malloc(Total_Dimensions * sizeof(float));
    }

    // 解码
    char Encoded_Str[1000]; // 单一块字符串
    char Standard_No[4]; // 标准编号
    char Block_No[4]; // 块编号
    bool Calibration_Monitor = true; // 校验监控器
    char Xy_train_Str[Num_Training_Samples][Total_Dimensions][10];
    char Xy_train_Str_Block[Block_Size][Total_Dimensions][10];
    for(int i=0;i<Number_Participants;i++)
    {
        if(i != (Number_Participants - 1))
        {
            for(int j=Validator;j<Validator+1;j++)
            {
                // strcpy(Encoded_Str,Block_Str[0][i]); // 取出单一块字符串
                size_t Str_Length = strlen(Block_Str[0][i]);
                memcpy(Encoded_Str,Block_Str[0][i],Str_Length);
                Encoded_Str[Str_Length] = '\0';

                //块编号校验
                // sprintf(Standard_No,"%03d",j); // 获取标准编号
                snprintf(Standard_No,sizeof(Standard_No),"%03d",j);
                strncpy(Block_No,Encoded_Str,3); // 读出块编号
                Block_No[3] = '\0'; // 以'\0'结束
                if(strcmp(Block_No,Standard_No) == 1)
                {
                    Calibration_Monitor = false;
                }

                //块分解
                for(int m=0;m<Block_Size;m++) // m<5
                {
                    for(int n=0;n<Participants[i];n++) // n<3
                        {
                            strncpy(Xy_train_Str[Block_Size*j+m][Participants[i]*i+n],Encoded_Str + (3+(4*Participants[i])*m+4*n),4);
                            Xy_train_Str[Block_Size*j+m][Participants[i]*i+n][4]='\0';

                            // 写入Xy_train_Str_Block
                            // strcpy(Xy_train_Str_Block[m][Participants[i]*i+n],Xy_train_Str[Block_Size*j+m][Participants[i]*i+n]);
                            Str_Length = strlen(Xy_train_Str[Block_Size*j+m][Participants[i]*i+n]);
                            memcpy(Xy_train_Str_Block[m][Participants[i]*i+n],Xy_train_Str[Block_Size*j+m][Participants[i]*i+n],Str_Length);
                            Xy_train_Str_Block[m][Participants[i]*i+n][Str_Length] = '\0';
                        }
                }
            }
        }
        else // 拥有标签数据的参与方
        {
            for(int j=Validator;j<Validator+1;j++)
            {
                // strcpy(Encoded_Str,Block_Str[0][i]); // 取出单一块字符串
                size_t Str_Length = strlen(Block_Str[0][i]);
                memcpy(Encoded_Str,Block_Str[0][i],Str_Length);
                Encoded_Str[Str_Length] = '\0';

                //块编号校验
                // sprintf(Standard_No,"%03d",j); // 获取标准编号
                snprintf(Standard_No,sizeof(Standard_No),"%03d",j);
                strncpy(Block_No,Encoded_Str,3); // 读出块编号
                Block_No[3] = '\0'; // 以'\0'结束
                if(strcmp(Block_No,Standard_No) == 1)
                {
                    Calibration_Monitor = false;
                }

                //块分解
                for(int m=0;m<Block_Size;m++) // m<5
                {
                    for(int n=0;n<(Participants[Number_Participants-1] - 1);n++) // n<3-1(Dia) / n<4-1(Brea)
                    {
                        strncpy(Xy_train_Str[Block_Size*j+m][(Number_Participants-1)*Participants[0]+n],Encoded_Str + (3+(4*(Participants[Number_Participants-1]-1)+5)*m+4*n),4);
                        Xy_train_Str[Block_Size*j+m][(Number_Participants-1)*Participants[0]+n][4] = '\0';

                        // 写入Xy_train_Str_Block
                        // strcpy(Xy_train_Str_Block[m][(Number_Participants-1)*Participants[0]+n],Xy_train_Str[Block_Size*j+m][(Number_Participants-1)*Participants[0]+n]);
                        Str_Length = strlen(Xy_train_Str[Block_Size*j+m][(Number_Participants-1)*Participants[0]+n]);
                        memcpy(Xy_train_Str_Block[m][(Number_Participants-1)*Participants[0]+n],Xy_train_Str[Block_Size*j+m][(Number_Participants-1)*Participants[0]+n],Str_Length);
                        Xy_train_Str_Block[m][(Number_Participants-1)*Participants[0]+n][Str_Length] = '\0';
                    }
                    //标签数据
                    strncpy(Xy_train_Str[Block_Size*j+m][(Number_Participants-1)*Participants[0] + Participants[Number_Participants-1] - 1],Encoded_Str + (3 + (4*(Participants[Number_Participants-1] - 1)) + ((4*(Participants[Number_Participants-1]-1) + 5)*m)),5);
                    Xy_train_Str[Block_Size*j+m][(Number_Participants-1)*Participants[0] + Participants[Number_Participants-1] - 1][5] = '\0';

                    // 写入Xy_train_Str_Block
                    // strcpy(Xy_train_Str_Block[m][(Number_Participants-1)*Participants[0] + Participants[Number_Participants-1] - 1],Xy_train_Str[Block_Size*j+m][(Number_Participants-1)*Participants[0] + Participants[Number_Participants-1] - 1]);
                    Str_Length = strlen(Xy_train_Str[Block_Size*j+m][(Number_Participants-1)*Participants[0] + Participants[Number_Participants-1] - 1]);
                    memcpy(Xy_train_Str_Block[m][(Number_Participants-1)*Participants[0] + Participants[Number_Participants-1] - 1],Xy_train_Str[Block_Size*j+m][(Number_Participants-1)*Participants[0] + Participants[Number_Participants-1] - 1],Str_Length);
                    Xy_train_Str_Block[m][(Number_Participants-1)*Participants[0] + Participants[Number_Participants-1] - 1][Str_Length] = '\0';
                }
            }
        }
    }

    // 返回校验结果
    if(!Calibration_Monitor)
    {
        printf("Block number verification failed!");
    }

    // 打印XY_train_Str_Block
    // printf("\nXy_train_Str_Block\n");
    // for(int i=0;i<Block_Size;i++)
    // {
    //     for(int j=0;j<Total_Dimensions;j++)
    //     {
    //         printf("%s ",Xy_train_Str_Block[i][j]);
    //     }
    //     printf("\n");
    // }

    // 字符串->数值
    for(int i=0;i<Num_Training_Samples;i++)
    {
        for(int j=0;j<Total_Dimensions;j++)
        {
            Xy_train[i][j] = atoi(Xy_train_Str_Block[i][j]) / 10000.0;
        }
    }

    // 打印XY_train
    // printf("\nXy_train\n");
    // for(int i=0;i<Block_Size;i++)
    // {
    //     for(int j=0;j<Total_Dimensions;j++)
    //     {
    //         printf("%.4f ",Xy_train[i][j]);
    //     }
    //     printf("\n");
    // }

    //return Xy_train;
    for(int i=0;i<Block_Size;i++)
    {
        for(int j=0;j<Total_Dimensions;j++)
        {
            (*Xy_train_Output)[i][j] = Xy_train[i][j];
        }
    }

    // free掉Xy_train的内存
    for(int i=0;i<Num_Training_Samples;i++)
    {
        free(Xy_train[i]);
    }
    free(Xy_train);
}

// h函数，M是特征数（Dia: M=8 ; Brea: M=9）
float h(float* theta,float* x,int M)
{
    float h_value = theta[0];

    for(int m=0;m<M;m++)
    {
        h_value = h_value + theta[m+1] * x[m];
    }
    
    return h_value;
}

// 预测值计算函数
float Predictive_value_calculation(float* theta,float* x,int M)
{
    float y_predicted;
    float h_value;

    h_value = h(theta,x,M);
    y_predicted = 1/(1+exp((-1)*h_value));

    return y_predicted;
}

// 模型参数更新函数
void update(float** theta_updated_Output,float* theta_t,float** Xy_train,int M,int Block_Size,int Num_Block,float alpha)
{
    float* theta_updated = (float*)malloc((M+1) * sizeof(float));
    // 初始化
    for(int m=0;m<M+1;m++)
    {
        theta_updated[m] = 0.0;
    }

    // 标签分离
    float X_train[Block_Size][M];
    float y_trian[Block_Size][1];
    for(int i=0;i<Block_Size;i++)
    {
        y_trian[i][0] = Xy_train[i][M];
        for(int m=0;m<M;m++)
        {
            X_train[i][m] = Xy_train[i][m];
        }
    }

    // 参数更新
    float y_predicted_n;
    float y_n;
    for(int i=0;i<Block_Size;i++)
    {
        y_predicted_n = Predictive_value_calculation(theta_t,X_train[i],M);
        y_n = y_trian[i][0];

        theta_updated[0] = theta_updated[0] + (y_predicted_n - y_n);

        for(int m=0;m<M;m++)
        {
            theta_updated[m+1] = theta_updated[m+1] + (y_predicted_n - y_n)*X_train[i][m];
        }
    }

    for(int m=0;m<M+1;m++)
    {
        theta_updated[m] = theta_t[m] - (alpha/Block_Size)*theta_updated[m];
    }

    // return theta_updated;
    for(int m=0;m<M+1;m++)
    {
        (*theta_updated_Output)[m] = theta_updated[m];
    }

    // free掉theta_updated的内存
    free(theta_updated);
}

// 块字符串解密
void Batch_Str_Decryption(char**** Batch_Str_D_Output,char*** Batch_Str,int Number_Participants,unsigned char* ivec)
{
    // Batch_Str_D_Output用来接解密后的块串
    // Batch_Str是加密后的块串
    // Number_Participants是Batch_Str_D和Batch_Str的列数
    // 杀了我吧老子不想写了

    // 定义Batch_Str_D，最后记得free掉
    char*** Batch_Str_D = (char***)malloc(1 * sizeof(char**));
    Batch_Str_D[0] = (char**)malloc(Number_Participants * sizeof(char*));
    for(int i=0;i<Number_Participants;i++)
    {
        Batch_Str_D[0][i] = (char*)malloc(1000 * sizeof(char));
    }

    for(int j=0;j<Number_Participants;j++)
    {
        // 获取第j个参与方的加密块串
        char* Str_cipher = Batch_Str[0][j];
        int cipher_Len = strlen(Str_cipher);

        // 解密后的明文长度等于密文长度
        int plain_Len = cipher_Len;

        // 初始化解密的IV
        unsigned char ivec_copy[AES_BLOCK_SIZE];
        memcpy(ivec_copy,ivec,AES_BLOCK_SIZE);

        // 解密！
        AES_cbc_encrypt((unsigned char*)Str_cipher, (unsigned char*)Batch_Str_D[0][j],cipher_Len,&aes_key,ivec_copy,AES_DECRYPT);

        // 添加终止符
        Batch_Str_D[0][j][plain_Len] = '\0';
    }

    // 写入Batch_Str_D_Output
    for(int j=0;j<Number_Participants;j++)
    {
        (*Batch_Str_D_Output)[0][j] = Batch_Str_D[0][j];
    }

    // 打印Batch_Str_D
    for(int j=0;j<Number_Participants;j++)
    {
        printf("%s ",Batch_Str_D);
    }
    printf("\n");

    // free掉Batch_Str_D
    for(int i=0;i<Number_Participants;i++)
    {
        free(Batch_Str_D[0][i]);
    }
    free(Batch_Str_D[0]);
    free(Batch_Str_D);
}

/* version 2.0 202408281336 */