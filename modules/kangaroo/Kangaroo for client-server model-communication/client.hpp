#include <seal/seal.h>
#include <sys/time.h>
#include <iostream>
#include "examples.h"
#include <chrono>
#include <ctime>   // include time()
#include <cmath>
#include <iostream>
#include <vector>
#include "BFSdectree.hpp"

class Client {
public:
    // The key parameters required by the client.
    shared_ptr<SEALContext> context;
    unique_ptr<KeyGenerator> keygen;
    unique_ptr<PublicKey> public_key;
    unique_ptr<RelinKeys> relin_keys;
    unique_ptr<GaloisKeys> gal_keys;
    unique_ptr<Encryptor> encryptor;
    unique_ptr<Evaluator> evaluator;
    unique_ptr<Decryptor> decryptor;
    unique_ptr<BatchEncoder> encoder;
    size_t poly_modulus_degree;

    // The dimension of the feature vector of the client
    int M;

    Client(int Np) {
        client_initial_keys(Np);
    }

    void client_initial_keys(int Np) {
        EncryptionParameters parms(scheme_type::bfv);
        poly_modulus_degree = 1 << Np;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
        // parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree,25)); // Set an appropriate plaintext modulus
        // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {30, 30, 30}));
        parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 25)); // Set an appropriate plaintext modulus

        // Initialize SEALContext
        context = make_shared<SEALContext>(parms);

        // Initialize keygen, encryptor, evaluator, decryptor, encoder
        keygen = make_unique<KeyGenerator>(*context);
        public_key = make_unique<PublicKey>();
        keygen->create_public_key(*public_key);

        relin_keys = make_unique<RelinKeys>();
        keygen->create_relin_keys(*relin_keys);

        gal_keys = make_unique<GaloisKeys>();
        keygen->create_galois_keys(*gal_keys);  // BFV scheme may not require Galois keys

        encryptor = make_unique<Encryptor>(*context, *public_key);
        evaluator = make_unique<Evaluator>(*context);
        decryptor = make_unique<Decryptor>(*context, keygen->secret_key());
        encoder = make_unique<BatchEncoder>(*context);
    }

    Ciphertext client_Load_vector(int M_size, vector<int64_t> x) {
        M = M_size;
        Plaintext x_plain;

        // Here, repeatedly expand the X vector to fill the entire vector
        int j = 0;
        for (size_t i = M; i < poly_modulus_degree; i++) {
            x.push_back(x[j]);
            j = (j + 1) % M;
        }
        cout << "Input the encoding vector of the client: " << endl;
        print_vector(x, 24, 0);
        encoder->encode(x, x_plain); // Use an integer encoder
        Ciphertext x_encrypted;
        encryptor->encrypt(x_plain, x_encrypted);
        return x_encrypted;
    }

    // When sign is true, it is the first comparison, otherwise it is the second comparison
    Ciphertext client_decrypt_compare_result(Ciphertext x_encrypted, bool sign){
        Plaintext x_plain;
        vector<int64_t> x;

        decryptor->decrypt(x_encrypted, x_plain);
        encoder->decode(x_plain, x);
        cout << "Output the client's vector AR * (X - Y) + BR: ";
        print_vector(x, 24, 0);

        vector<int64_t> I1;
        I1.reserve(poly_modulus_degree);
        if(sign){
            for (size_t i = 0; i < poly_modulus_degree; i++) {
                if (x[i] < 0 && i % M == 0){
                    I1.push_back(0);
                }else{
                    I1.push_back(1);
                }
            }
        }else{
            for (size_t i = 0; i < poly_modulus_degree; i++) {
                if (x[i] < 0){
                    I1.push_back(0);
                }else{
                    I1.push_back(1);
                }
            }
        }
        cout << "Client-side decryption, output vector I1: ";
        print_vector(I1, 24, 0); 

        Plaintext I1_plain;
        encoder->encode(I1, I1_plain);
        Ciphertext I1_encrypted;
        encryptor->encrypt(I1_plain, I1_encrypted);

        return I1_encrypted;
    }

    Ciphertext client_construct_path_sum(Ciphertext I1_encrypted, int length){
        Plaintext x_plain;
        vector<int64_t> x;
        decryptor->decrypt(I1_encrypted, x_plain);
        encoder->decode(x_plain, x);
        
        vector<int64_t> Extract_x;
        for (size_t i = 0; i < poly_modulus_degree; i++)
        {
            if ((i % M == 0) && (Extract_x.size() < length)) {
                Extract_x.push_back(x[i]);
            }
        }
        cout << "The client decrypts to obtain the perturbation vector and outputs the I' vector: ";
        print_vector(x, 24, 0);
        cout << "The client extracts the I' vector to obtain Extract_x: " << Extract_x.size();
        print_vector(Extract_x, 24, 0);

        vector<int64_t> ClientPathSum = testTreeSumPath(Extract_x, true);   
        Plaintext ClientPathSum_plain;
        encoder->encode(ClientPathSum, ClientPathSum_plain);
        encryptor->encrypt(ClientPathSum_plain, I1_encrypted);
        return I1_encrypted;
    }

};