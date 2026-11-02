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


class Server {
public:
    // The key parameters required by the server
    const PublicKey* public_key;
    const RelinKeys* relin_keys;
    const GaloisKeys* gal_keys;
    const Encryptor* encryptor;
    const Evaluator* evaluator;
    unique_ptr<BatchEncoder> encoder;
    size_t poly_modulus_degree;

    // Feature dimension and the total number of decision nodes.
    int M, decNodeNumber;

    int64_t T2sum = 0;

    // Server model parameters: y represents the split threshold for each node, weight represents the leaf node weights, and S represents the feature selection positions
    Plaintext y_plain, weight_plain, S_plain;

    // Parameters generated during the first secure comparison
    Plaintext A_plain, B_plain, R_plain, C1_plain, R1_plain, Extract_R1_plain;

    // Parameters generated during the second secure comparison
    Plaintext A1_plain, B1_plain, R2_plain, C2_plain;

    // Server-side path summation results and masks
    Plaintext SeverPathSum_plain, T2_plain;
    
    Server(int Np, int M, vector<int64_t> Node_y, vector<int64_t> weight, vector<int64_t> index){
        EncryptionParameters parms(scheme_type::bfv);
        poly_modulus_degree = 1 << Np;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
        // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {30, 30, 30}));
        parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 25)); // Set an appropriate plaintext modulus

        // 1. Initialize SEALContext
        shared_ptr<SEALContext> context = make_shared<SEALContext>(parms);

        // 2. Initialize encoder
        encoder = make_unique<BatchEncoder>(*context);    

        vector<int64_t> y;

        this->M = M;
        this->decNodeNumber = index.size();

        // 3. The server generates parameters related to the first secure comparison
        int temp = 0;
        for (size_t i = 0; i < poly_modulus_degree; i++) {
            if ((i % M == 0) && (temp < index.size())) {
                // Parameters required for the first secure comparison
                y.push_back(Node_y[temp]);
                temp++;
            } else {
                // Parameters required for the first secure comparison
                y.push_back(0);
            }
        }

        // 4. Extract the feature index vector
        vector<int64_t> S;
        int j = 0;
        for (size_t i = 1; i <= poly_modulus_degree; i++) {
            if (j < index.size()) {
                if ((i-1) % M == index[j]) {
                    S.push_back(1);
                } else {
                    S.push_back(0);
                }
            } else {
                S.push_back(0);
            }
            if (i % M == 0) {
                j++;
            }
        }
        cout << "Input extraction index: " << endl;
        print_vector(S, 24, 0);

        // 5. The encoder, decision node thresholds, weights, and feature indices can be reused
        encoder->encode(y, y_plain);
        encoder->encode(weight, weight_plain);
        encoder->encode(S, S_plain);
    }


    // The constructor uses pointers instead of directly copying objects
    void server_initial_cryptosystem(const PublicKey* public_key, const RelinKeys* relin_keys, const GaloisKeys* gal_keys,
           const Encryptor* encryptor, const Evaluator* evaluator) {
        this->public_key = public_key;
        this->relin_keys = relin_keys;
        this->gal_keys = gal_keys;
        this->encryptor = encryptor;
        this->evaluator = evaluator;
    }

    void server_initial_system(vector<int64_t> index_true){
        //  The parameters here are generated for the first secure comparison
        vector<int64_t> A, B, R, C1, R1;
        //  The parameters here are generated for the second secure comparison
        vector<int64_t> A1, B1, R2, C2;
        vector<int64_t> Extract_R1, T2;

        // 1. The server generates parameters related to the first secure comparison
        int temp = 0;
        for (size_t i = 0; i < poly_modulus_degree; i++) {
            if ((i % M == 0) && (Extract_R1.size() < decNodeNumber)) {
                // Parameters required for the first secure comparison
                A.push_back(static_cast<int64_t>(random(1.0, 1000.0)));
                B.push_back(A.back() - static_cast<int64_t>(random(1.0, A.back())));
                R.push_back(random(0, 10000) >= 5000 ? -1 : 1);
                C1.push_back(R.back() == -1 ? 1 : 0);
                R1.push_back(static_cast<int64_t>(random(1.0, 1000.0)));
                Extract_R1.push_back(R1.back());
                temp++;
            } else {
                // Parameters required for the first secure comparison
                A.push_back(0);
                B.push_back(0);
                R.push_back(0);
                C1.push_back(0);
                R1.push_back(0);
            }
            T2.push_back(random(0, 1000));
            T2sum += T2[i];
        }

        cout << "The server generates a random mask vector T2 vector: " << endl;
        print_vector(T2, 24, 0);
        cout << "The server generates a random mask vector R1 vector: " << Extract_R1.size() << endl;
        print_vector(Extract_R1, 24, 0);

        // 2. The server sums the masked paths
        vector<int64_t> SeverPathSum = testTreeSumPath(Extract_R1, false);

        // 3. The server generates parameters related to the second secure comparison
        encoder->encode(SeverPathSum, SeverPathSum_plain);   
        for (size_t i = 0; i < SeverPathSum.size(); i++)
        {
            // Parameters required for the second secure comparison, where all paths, including virtual paths, are masked to protect the tree structure
            A1.push_back(static_cast<int64_t>(random(1.0, 1000.0)));
            B1.push_back(A1.back() - static_cast<int64_t>(random(1.0, A1.back())));
            R2.push_back(random(0, 10000) >= 5000 ? -1 : 1);
            C2.push_back(R2.back() == -1 ? 1 : 0);
        }
        for (size_t i = 0; i < A.size(); i++) {
            A[i] *= R[i]; // Calculate AR
            B[i] *= R[i]; // Calculate BR
        }
        
        scaleVector(index_true, M);
        for (size_t i = 0; i < poly_modulus_degree; i++)
        {
            if(i % M == 0 && !contains(index_true, i)){
                R[i] = 0; // Calculate the result beyond the node and replace it with 0
                C1[i] = 0; // Calculate BR
            }
        }

        for (size_t i = 0; i < A1.size(); i++)
        {
            A1[i] *= (-R2[i]); // Calculate AR
            B1[i] *= R2[i]; // Calculate BR
        }

        // The server encodes the relevant information
        encoder->encode(A, A_plain);
        encoder->encode(B, B_plain);
        encoder->encode(R, R_plain);
        encoder->encode(C1, C1_plain);
        encoder->encode(R1, R1_plain);

        // Masks and weights required for the second comparison calculation
        encoder->encode(A1, A1_plain);
        encoder->encode(B1, B1_plain);
        encoder->encode(R2, R2_plain);
        encoder->encode(C2, C2_plain);
        encoder->encode(T2, T2_plain);
    }

    Ciphertext server_secure_feature_selection(Ciphertext x_encrypted){
        evaluator->multiply_plain_inplace(x_encrypted, S_plain);
        bool Mis2Power = (M > 0) && ((M & (M - 1)) == 0);
        if (Mis2Power)
        {
            for (size_t i = 0; i <= static_cast<int>(log(M)); i++)
            {
                int galois_element = static_cast<int>(pow(2, i));
                Ciphertext x1_encrypted;
                evaluator->rotate_rows(x_encrypted, galois_element, *gal_keys, x1_encrypted); // Rotate
                evaluator->add_inplace(x_encrypted, x1_encrypted);
            }
        }else{
            Ciphertext x2_encrypted;
            Ciphertext x1_encrypted;
            evaluator->rotate_rows(x_encrypted, 1, *gal_keys, x1_encrypted);
            evaluator->add(x_encrypted, x1_encrypted, x2_encrypted);
            if (M % 2 ==0)
            {
                x_encrypted = x2_encrypted;
            }
            
            int64_t logM = std::ceil(std::log2(M));
            int temp = M;

            for (int64_t i = 1; i < logM - 1; i++) {
                temp = temp - std::floor(temp / 2);
                int galois_element = static_cast<int>(pow(2, i));
                if (temp % 2 == 0) {
                    evaluator->rotate_rows(x_encrypted, galois_element, *gal_keys, x_encrypted);
                    evaluator->add_inplace(x_encrypted, x2_encrypted);
                }   
                evaluator->rotate_rows(x2_encrypted, galois_element, *gal_keys, x1_encrypted);
                evaluator->add_inplace(x2_encrypted, x1_encrypted);
            }
            int galois_element = static_cast<int>(pow(2, logM-1));
            evaluator->rotate_rows(x_encrypted, galois_element, *gal_keys, x_encrypted);
            evaluator->add_inplace(x_encrypted, x2_encrypted);
        }
        return x_encrypted;
    }

    Ciphertext server_secure_compare(Ciphertext x_encrypted, Plaintext A_plain, Plaintext B_plain){
        // 1. Perturb the difference: (X-Y)*AR + BR
        evaluator->multiply_plain_inplace(x_encrypted, A_plain);
        evaluator->add_plain_inplace(x_encrypted, B_plain);
        return x_encrypted;
    }

    Ciphertext server_recover_vector(Ciphertext I1_encrypted, Plaintext R_plain, Plaintext C1_plain){
        // 1. The server recovers the comparison result vector
        evaluator->multiply_plain_inplace(I1_encrypted, R_plain);
        evaluator->add_plain_inplace(I1_encrypted, C1_plain);

        return I1_encrypted;
    }

    Ciphertext server_calculate_weight(Ciphertext I1_encrypted, Plaintext T2_plain){
        evaluator->multiply_plain_inplace(I1_encrypted, weight_plain);
        evaluator->add_plain_inplace(I1_encrypted, T2_plain);
        return I1_encrypted;
    }
	
};