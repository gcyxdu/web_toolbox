#include <seal/seal.h>
#include <sys/time.h>
#include <iostream>
#include "examples.h"
#include <chrono>
#include <ctime> // include time()
#include <cmath>
#include <iostream>
#include <vector>
#include <cassert>
#include "BFSdectree.hpp"

using namespace seal;
using namespace std;

constexpr int K = 1;

struct timeval time1, time2;
float timeuse;

double random(double start, double end)
{
	return start + (end - start) * rand() / (RAND_MAX + 1.0);
}

int random(int min, int max)
{
	static std::random_device rd;							   // Obtain the random seed
	static std::mt19937 generator(rd());					   // Generate random numbers using the Mersenne Twister algorithm
	std::uniform_int_distribution<int> distribution(min, max); // Uniform distribution
	return distribution(generator);							   // Generate random numbers
}

struct TreeNode
{
	int left_weight;  // Left weight
	int right_weight; // Right weight
	TreeNode *left;	  // Left child node
	TreeNode *right;  // Right child node

	TreeNode(double left_w, double right_w)
		: left_weight(left_w), right_weight(right_w), left(nullptr), right(nullptr) {}
};

class Tree
{
public:
	TreeNode *root;
	vector<int64_t> sumweight;

	Tree() : root(nullptr) {}

	void buildTree(const std::vector<int64_t> &values, bool YesOrNo, vector<int64_t> structureIndex)
	{
		if (values.empty())
			return;
		if (YesOrNo)
		{
			root = buildRecursive(values, 1, structureIndex);
		}
		else
		{
			root = buildReverseRecursive(values, 1, structureIndex);
		}
	}

	void printTree(TreeNode *node)
	{
		if (node != nullptr)
		{
			// std::cout << ", Left Weight: " << node->left_weight
			//   << ", Right Weight: " << node->right_weight << std::endl;
			printTree(node->left);
			printTree(node->right);
		}
	}

	void sumPaths(int64_t weight, TreeNode *node, int current_sum)
	{
		if (node == nullptr)
			return;

		// Update the sum of the current path
		current_sum += weight;

		// If a leaf node is reached, print the sum of the current path
		if (node->left == nullptr && node->right == nullptr)
		{
			sumweight.push_back(current_sum + node->left_weight);
			sumweight.push_back(current_sum + node->right_weight);
		}
		else
		{
			sumPaths(node->left_weight, node->left, current_sum);	// Recursively traverse the left subtree
			sumPaths(node->right_weight, node->right, current_sum); // Recursively traverse the right subtree
		}
	}

private:
	TreeNode *buildRecursive(const std::vector<int64_t> &values, int index, vector<int64_t> structureIndex)
	{
		unordered_map<int64_t, TreeNode *> nodes;

		// Create all nodes and store them in a hash table
		for (size_t i = 0; i < structureIndex.size(); ++i)
		{
			int index = structureIndex[i];
			double left_weight = values[i];
			double right_weight = 1 - left_weight;
			nodes[index] = new TreeNode(left_weight, right_weight);
		}

		// Connect the left and right child nodes for each node
		for (size_t i = 0; i < structureIndex.size(); ++i)
		{
			int index = structureIndex[i];

			// Retrieve the parent node
			TreeNode *currentNode = nodes[index];

			// Calculate the indices of the left and right child nodes
			int leftIndex = 2 * index;
			int rightIndex = 2 * index + 1;

			// Associate the existing left and right child nodes with the current node
			if (nodes.find(leftIndex) != nodes.end())
			{
				currentNode->left = nodes[leftIndex];
			}
			if (nodes.find(rightIndex) != nodes.end())
			{
				currentNode->right = nodes[rightIndex];
			}
		}

		// Return the root node, assuming the root node's index is 1.
		return nodes[1];
	}

	TreeNode *buildReverseRecursive(const std::vector<int64_t> &values, int index, vector<int64_t> structureIndex)
	{
		unordered_map<int64_t, TreeNode *> nodes;

		// Create all nodes and store them in a hash table
		for (size_t i = 0; i < structureIndex.size(); ++i)
		{
			int index = structureIndex[i];
			double left_weight = -values[i];
			double right_weight = -left_weight;
			nodes[index] = new TreeNode(left_weight, right_weight);
		}

		// Connect the left and right child nodes for each node
		for (size_t i = 0; i < structureIndex.size(); ++i)
		{
			int index = structureIndex[i];

			// Retrieve the parent node
			TreeNode *currentNode = nodes[index];

			// Calculate the indices of the left and right child nodes
			int leftIndex = 2 * index;
			int rightIndex = 2 * index + 1;

			// Associate the existing left and right child nodes with the current node
			if (nodes.find(leftIndex) != nodes.end())
			{
				currentNode->left = nodes[leftIndex];
			}
			if (nodes.find(rightIndex) != nodes.end())
			{
				currentNode->right = nodes[rightIndex];
			}
		}

		// Return the root node, assuming the root node's index is 1
		return nodes[1];
	}
};

vector<int64_t> testTreeSumPath(vector<int64_t> values, bool YesOrNo, vector<int64_t> structureIndex)
{
	Tree tree;
	tree.buildTree(values, YesOrNo, structureIndex);

	// std::cout << "Tree structure:" << std::endl;
	// tree.printTree(tree.root);

	// std::cout << "Path sums:" << std::endl;
	tree.sumPaths(0, tree.root, 0); // Calculate the path sum starting from the root node
	// print_vector(tree.sumweight, 24, 0); // Display the integer with precision set to 0

	return tree.sumweight;
}

vector<int64_t> encodeVector(vector<int64_t> a, int M, int length)
{
	std::vector<int64_t> result;

	// Traverse the original vector
	for (size_t i = 0; i < a.size(); ++i)
	{
		// Add the current value to the result vector
		result.push_back(a[i]);

		// Insert M-1 zeros
		for (int j = 1; j < M; ++j)
		{
			result.push_back(0);
		}
	}

	for (size_t i = a.size() * M; i < length; i++)
	{
		result.push_back(0);
	}

	return result;
}

vector<int64_t> Extract_vector(vector<int64_t> a, int index, int length, int dim)
{
	vector<int64_t> result;
	for (size_t i = 0; i < length; i++)
	{
		result.push_back(a[i * dim + index]);
	}
	return result;
}

class Client
{
public:
	const PublicKey *public_key;
	const Encryptor *encryptor;
	const Evaluator *evaluator;
	const BatchEncoder *encoder;
	size_t poly_modulus_degree;

	Ciphertext x_cipher;

	Client(int Np, vector<int64_t> x, const PublicKey *public_key, const Encryptor *encryptor, const Evaluator *evaluator, const BatchEncoder *encoder)
	{
		this->poly_modulus_degree = 1 << Np;
		this->public_key = public_key;
		this->encryptor = encryptor;
		this->evaluator = evaluator;
		this->encoder = encoder;

		vector<int64_t> xx;
		int temp = this->poly_modulus_degree / x.size();
		for (size_t i = 0; i < poly_modulus_degree; i++)
		{
			if (temp > 0)
			{
				xx.push_back(x[i % x.size()]);
				if ((i + 1) % x.size() == 0)
				{
					temp--;
				}
			}
			else
			{
				xx.push_back(0);
			}
		}

		Plaintext x_plain;
		encoder->encode(xx, x_plain);
		encryptor->encrypt(x_plain, x_cipher);
	}
};

// Scale the elements of the vector by a factor of M
void scaleVector(std::vector<int64_t> &vec, int64_t M)
{
	for (auto &val : vec)
	{
		val *= M; // Multiply each element by M
	}
}

class CSP
{
public:
	// Key parameters required by the server
	const PublicKey *public_key;
	const RelinKeys *relin_keys;
	const GaloisKeys *gal_keys;
	const Encryptor *encryptor;
	const Evaluator *evaluator;
	const BatchEncoder *encoder;
	size_t poly_modulus_degree;

	// Feature dimension and the total number of decision nodes
	int M, decNodeNumber;

	int64_t T2sum = 0;

	// Server-side model parameters: y represents the split threshold for each node, weight denotes the leaf node weights, and S indicates the feature selection positions
	Ciphertext y_cipher, weight_cipher, TrueIndex;
	vector<Ciphertext> S_cipher;

	// Parameters generated during the first secure comparison
	Plaintext A_plain, B_plain, R1_plain, Extract_R1_plain;
	Ciphertext R_cipher, C1_cipher;

	// Parameters generated during the second secure comparison
	Plaintext A1_plain, B1_plain, R2_plain, C2_plain;

	// Server-side path summation result and mask
	vector<Plaintext> Random_plain, cspPathSum_plain;
	Plaintext T2_plain, Random_sum_plain;

	CSP(int Np, int M, Ciphertext y_cipher, Ciphertext weight_cipher, vector<Ciphertext> S_cipher, Ciphertext TrueIndex, const PublicKey *public_key, const RelinKeys *relin_keys, const GaloisKeys *gal_keys, const Encryptor *encryptor, const Evaluator *evaluator, const BatchEncoder *encoder)
	{
		this->public_key = public_key;
		this->relin_keys = relin_keys;
		this->gal_keys = gal_keys;
		this->encryptor = encryptor;
		this->evaluator = evaluator;
		this->encoder = encoder;

		this->poly_modulus_degree = 1 << Np;
		this->M = M;

		this->y_cipher = y_cipher;
		this->weight_cipher = weight_cipher;
		this->S_cipher = S_cipher;
		this->TrueIndex = TrueIndex;
	}

	void csp_initial_system(int PackTreeNum, vector<int64_t> structureIndex, bool ifInteractive)
	{
		// Here, the parameters are generated for the first secure comparison
		vector<int64_t> A, B, R, C1, R1;
		// Here, the parameters are generated for the second secure comparison
		vector<int64_t> A1, B1, R2, C2;
		vector<int64_t> Extract_R1, T2, RandomSum;

		int length = poly_modulus_degree / M - 1;
		decNodeNumber = length;

		// 1.1. The server generates parameters related to the first secure comparison
		int temp = 0;
		for (size_t i = 0; i < poly_modulus_degree; i++)
		{
			// The first secure comparison requires parameters
			A.push_back(static_cast<int64_t>(random(1.0, 1000.0)));
			B.push_back(A.back() - static_cast<int64_t>(random(1.0, A.back())));
			R.push_back(random(0, 10000) >= 5000 ? -1 : 1);
			R1.push_back(static_cast<int64_t>(random(1.0, 1000.0)));
			C1.push_back(R.back() == -1 ? 1 : 0);
			T2.push_back(random(0, 1000));
			RandomSum.push_back(0);
			T2sum += T2[i];
		}

		for (size_t i = 0; i < PackTreeNum; i++)
		{
			// 2.1 Extract the corresponding vector
			Extract_R1 = Extract_vector(R1, i, decNodeNumber, M);

			// 2.2 The server performs summation on the masked path
			vector<int64_t> SeverPathSum = testTreeSumPath(Extract_R1, false, structureIndex);

			// 2.3 The server encodes the mask
			Plaintext temp;
			encoder->encode(SeverPathSum, temp);
			cspPathSum_plain.push_back(temp);

			// 2.4 If it is interactive feature selection
			if (ifInteractive)
			{
				int temp_sum = 0;
				vector<int64_t> RandomforSelect;
				Plaintext temp;
				for (size_t j = 0; j < poly_modulus_degree; j++)
				{
					int64_t random_value = random(1.0, 10000.0); // Generate random numbers
					RandomforSelect.push_back(random_value);

					if (j < decNodeNumber * M)
					{
						// Accumulate every M elements
						temp_sum -= random_value;
						if ((j + 1) % M == 0)
						{
							RandomSum[j + 1 - M + i] = temp_sum;
							temp_sum = 0; // Reset temp_sum
						}
					}
				}
				encoder->encode(RandomforSelect, temp);
				Random_plain.push_back(temp);
			}
		}

		if (ifInteractive)
		{
			encoder->encode(RandomSum, Random_sum_plain);
		}

		// 3. The server generates parameters related to the second secure comparison
		for (size_t i = 0; i < poly_modulus_degree; i++)
		{
			// Parameters required for the second secure comparison, where all paths including virtual paths are masked to protect the tree structure
			A1.push_back(static_cast<int64_t>(random(1.0, 1000.0)));
			B1.push_back(A1.back() - static_cast<int64_t>(random(1.0, A1.back())));
			R2.push_back(random(0, 10000) >= 5000 ? -1 : 1);
			C2.push_back(R2.back() == -1 ? 1 : 0);
		}
		for (size_t i = 0; i < poly_modulus_degree; i++)
		{
			A[i] *= R[i]; // Calculate AR
			B[i] *= R[i]; // Calculate BR
		}

		// Here, there should be an operation to restore R and C1, replacing the positions of virtual nodes with 0
		Plaintext R_plain, C1_plain;
		encoder->encode(R, R_plain);
		encoder->encode(C1, C1_plain);
		evaluator->multiply_plain(TrueIndex, R_plain, R_cipher);
		evaluator->multiply_plain(TrueIndex, C1_plain, C1_cipher);

		for (size_t i = 0; i < poly_modulus_degree; i++)
		{
			A1[i] *= (-R2[i]); // Calculate AR
			B1[i] *= R2[i];	   // Calculate BR
		}

		// The server encodes the relevant information
		encoder->encode(A, A_plain);
		encoder->encode(B, B_plain);
		encoder->encode(R1, R1_plain);

		// The mask and weights required for the second comparison calculation
		encoder->encode(A1, A1_plain);
		encoder->encode(B1, B1_plain);
		encoder->encode(R2, R2_plain);
		encoder->encode(C2, C2_plain);
		encoder->encode(T2, T2_plain);
	}

	Ciphertext csp_I_secure_feature_selection(Ciphertext x_encrypted, int index)
	{
		evaluator->multiply_inplace(x_encrypted, S_cipher[index]);
		evaluator->relinearize_inplace(x_encrypted, *relin_keys);
		bool Mis2Power = (M > 0) && ((M & (M - 1)) == 0);
		if (Mis2Power)
		{
			for (size_t i = 0; i <= static_cast<int>(log(M)); i++)
			{
				int galois_element = static_cast<int>(pow(2, i));
				Ciphertext x1_encrypted;
				evaluator->rotate_rows(x_encrypted, galois_element, *gal_keys, x1_encrypted); // Perform rotation
				evaluator->add_inplace(x_encrypted, x1_encrypted);
			}
		}
		else
		{
			Ciphertext x2_encrypted;
			Ciphertext x1_encrypted;
			evaluator->rotate_rows(x_encrypted, 1, *gal_keys, x1_encrypted);
			evaluator->add(x_encrypted, x1_encrypted, x2_encrypted);
			if (M % 2 == 0)
			{
				x_encrypted = x2_encrypted;
			}

			int64_t logM = std::ceil(std::log2(M));
			int temp = M;

			for (int64_t i = 1; i < logM - 1; i++)
			{
				temp = temp - std::floor(temp / 2);
				int galois_element = static_cast<int>(pow(2, i));
				if (temp % 2 == 0)
				{
					evaluator->rotate_rows(x_encrypted, galois_element, *gal_keys, x_encrypted);
					evaluator->add_inplace(x_encrypted, x2_encrypted);
				}
				evaluator->rotate_rows(x2_encrypted, galois_element, *gal_keys, x1_encrypted);
				evaluator->add_inplace(x2_encrypted, x1_encrypted);
			}
			int galois_element = static_cast<int>(pow(2, logM - 1));
			evaluator->rotate_rows(x_encrypted, galois_element, *gal_keys, x_encrypted);
			evaluator->add_inplace(x_encrypted, x2_encrypted);
		}
		return x_encrypted;
	}

	Ciphertext *csp_II_secure_feature_selection(Ciphertext x_cipher, int PackTreeNum)
	{
		Ciphertext *result = new Ciphertext[PackTreeNum];
		;
		for (size_t i = 0; i < PackTreeNum; i++)
		{
			evaluator->multiply(x_cipher, S_cipher[i], result[i]);
			evaluator->add_plain_inplace(result[i], Random_plain[i]);
		}
		return result;
	}

	Ciphertext csp_recover_selected_feature(Ciphertext x_cipher)
	{
		evaluator->add_plain_inplace(x_cipher, Random_sum_plain);
		return x_cipher;
	}

	Ciphertext csp_secure_compare(Ciphertext x_encrypted, Plaintext A_plain, Plaintext B_plain)
	{
		// 1. Apply perturbation to the difference (X-Y)AR + BR
		evaluator->multiply_plain_inplace(x_encrypted, A_plain);
		evaluator->add_plain_inplace(x_encrypted, B_plain);
		return x_encrypted;
	}

	Ciphertext csp_recover_vector(Ciphertext I1_encrypted, Ciphertext R_cipher, Ciphertext C1_cipher)
	{
		// 1. The server restores the comparison result vector
		evaluator->multiply_inplace(I1_encrypted, R_cipher);
		evaluator->add_inplace(I1_encrypted, C1_cipher);
		return I1_encrypted;
	}

	Ciphertext csp_recover_vector(Ciphertext I1_encrypted, Plaintext R_plain, Plaintext C1_plain)
	{
		// 1. The server restores the comparison result vector
		evaluator->multiply_plain_inplace(I1_encrypted, R_plain);
		evaluator->add_plain_inplace(I1_encrypted, C1_plain);

		return I1_encrypted;
	}

	Ciphertext csp_calculate_weight(Ciphertext I1_encrypted, Plaintext T2_plain)
	{
		evaluator->multiply_inplace(I1_encrypted, weight_cipher);
		evaluator->add_plain_inplace(I1_encrypted, T2_plain);
		return I1_encrypted;
	}
};

class Server
{
public:
	// Key parameters required by the server
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

	int M, decNodeNumber;

	vector<int64_t> isSwap;

	Plaintext plain_0;
	Ciphertext cipher0_1, cipher0_2, cipher0_3;

	Ciphertext y_cipher, weight_cipher, S_cipher, True_index;

	Server(int Np, int M, vector<int64_t> Node_y, vector<int64_t> weight, vector<int64_t> index, vector<int64_t> istrueNode, vector<int64_t> isSwap)
	{
		// 1. Initialize the encryption system parameters
		EncryptionParameters parms(scheme_type::bfv);
		poly_modulus_degree = 1 << Np;
		parms.set_poly_modulus_degree(poly_modulus_degree);
		parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
		// parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {30, 30, 30}));
		parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 50)); // Set an appropriate plaintext modulus

		// 1.1 Initialize the SEALContext
		context = make_shared<SEALContext>(parms);

		// 1.2 Initialize the keygen, encryptor, evaluator, decryptor, and encoder
		keygen = make_unique<KeyGenerator>(*context);
		public_key = make_unique<PublicKey>();
		keygen->create_public_key(*public_key);

		relin_keys = make_unique<RelinKeys>();
		keygen->create_relin_keys(*relin_keys);

		gal_keys = make_unique<GaloisKeys>();
		keygen->create_galois_keys(*gal_keys);

		encryptor = make_unique<Encryptor>(*context, *public_key);
		evaluator = make_unique<Evaluator>(*context);
		decryptor = make_unique<Decryptor>(*context, keygen->secret_key());
		encoder = make_unique<BatchEncoder>(*context);

		vector<int64_t> y, trueIndexVector;

		this->M = M;
		this->decNodeNumber = (1 << Np) / M - 1;
		this->isSwap = isSwap;

		// 2. Extract the corresponding threshold
		y = Node_y;
		int length = poly_modulus_degree / M - 1;

		// 3. Extract the feature index vector
		vector<int64_t> S;
		int j = 0;
		for (size_t i = 1; i <= poly_modulus_degree; i++)
		{
			if (j < index.size())
			{
				if ((i - 1) % M == index[j])
				{
					S.push_back(1);
				}
				else
				{
					S.push_back(0);
				}
			}
			else
			{
				S.push_back(0);
			}
			if (i % M == 0)
			{
				j++;
			}
		}

		Plaintext temp_plain;

		// 4. Encrypt the decision node thresholds, weights, feature indices, and real node indices
		encoder->encode(y, temp_plain);
		encryptor->encrypt(temp_plain, y_cipher);

		encoder->encode(weight, temp_plain);
		encryptor->encrypt(temp_plain, weight_cipher);

		encoder->encode(S, temp_plain);
		encryptor->encrypt(temp_plain, S_cipher);

		encoder->encode(istrueNode, temp_plain);
		encryptor->encrypt(temp_plain, True_index);
	}

	void server_init_inference()
	{
		vector<int64_t> zero_vector;
		for (size_t i = 0; i < poly_modulus_degree; i++)
		{
			zero_vector.push_back(0);
		}
		encoder->encode(zero_vector, plain_0);
		encryptor->encrypt(plain_0, cipher0_1);
		encryptor->encrypt(plain_0, cipher0_2);
		encryptor->encrypt(plain_0, cipher0_3);
	}

	Ciphertext server_secure_feature_selection(Ciphertext *x_encrypt, int PackTreeNum)
	{
		vector<int64_t> x_decrypt;
		Plaintext x_plain;
		Ciphertext x_cipher;

		int length = poly_modulus_degree / M - 1;

		for (size_t i = 0; i < poly_modulus_degree; i++)
		{
			x_decrypt.push_back(0);
		}

		for (size_t i = 0; i < PackTreeNum; i++)
		{
			vector<int64_t> temp;
			decryptor->decrypt(x_encrypt[i], x_plain);
			encoder->decode(x_plain, temp);
			int temp_sum = 0;
			for (size_t j = 0; j < poly_modulus_degree; j++)
			{
				if (j < length * M)
				{
					temp_sum += temp[j];
					if ((j + 1) % M == 0)
					{
						x_decrypt[j + 1 - M + i] = temp_sum;
						temp_sum = 0;
					}
				}
			}
		}
		encoder->encode(x_decrypt, x_plain);
		evaluator->add_plain(cipher0_1, x_plain, x_cipher);

		return x_cipher;
	}

	// When sign is true, it is the first comparison; otherwise, it is the second comparison
	Ciphertext server_decrypt_compare_result(Ciphertext x_encrypted, bool sign)
	{
		Plaintext x_plain;
		vector<int64_t> x;

		decryptor->decrypt(x_encrypted, x_plain);
		encoder->decode(x_plain, x);
		// cout << "Output the client's vector AR * (X-Y) + BR: ";
		// print_vector(x, 24, 0); // Display the integer with precision set to 0

		vector<int64_t> I1;
		I1.reserve(poly_modulus_degree);
		if (sign)
		{
			for (size_t i = 0; i < poly_modulus_degree; i++)
			{
				if (x[i] < 0 && isSwap[i] == 1)
				{
					I1.push_back(0);
				}
				else if (x[i] >= 0 && isSwap[i] == 1)
				{
					I1.push_back(1);
				}
				else if (x[i] >= 0 && isSwap[i] == -1)
				{
					I1.push_back(0);
				}
				else if (x[i] < 0 && isSwap[i] == -1)
				{
					I1.push_back(1);
				}
			}
		}
		else
		{
			for (size_t i = 0; i < poly_modulus_degree; i++)
			{
				if (x[i] < 0)
				{
					I1.push_back(0);
				}
				else
				{
					I1.push_back(1);
				}
			}
		}

		// cout << "The client decrypts and outputs the vector I1: ";
		// print_vector(I1, 24, 0); // Display the integer with precision set to 0

		Plaintext I1_plain;
		encoder->encode(I1, I1_plain);
		Ciphertext I1_encrypted;
		evaluator->add_plain(cipher0_2, I1_plain, I1_encrypted);
		encryptor->encrypt(I1_plain, I1_encrypted);

		return I1_encrypted;
	}

	Ciphertext server_construct_path_sum(Ciphertext I1_encrypted, vector<int64_t> structureIndex)
	{
		Plaintext x_plain;
		vector<int64_t> x;
		decryptor->decrypt(I1_encrypted, x_plain);
		encoder->decode(x_plain, x);

		vector<int64_t> Extract_x;
		for (size_t i = 0; i < poly_modulus_degree; i++)
		{
			if ((i % M == 0))
			{
				Extract_x.push_back(x[i]);
			}
		}

		// cout << "The client decrypts to obtain the perturbed result comparison vector I': ";
		// print_vector(x, 24, 0); // Display the integer with precision set to 0.
		// cout << "The client extracts the I' vector, obtaining Extract_x: " << Extract_x.size();
		// print_vector(Extract_x, 24, 0); // Display the integer with precision set to 0.

		vector<int64_t> serverPathSum = testTreeSumPath(Extract_x, true, structureIndex);
		Plaintext serverPathSum_plain;
		encoder->encode(serverPathSum, serverPathSum_plain);
		evaluator->add_plain(cipher0_3, serverPathSum_plain, I1_encrypted);

		return I1_encrypted;
	}
};

int main(int argc, char *argv[])
{
	// 1.1 The server reads the tree model
	const char *filename[7] = {
		"../UCI_dectrees/wine",		// m = 7  111
		"../UCI_dectrees/iris",		// m = 3
		"../UCI_dectrees/breast",	// m = 12  333
		"../UCI_dectrees/digits",	// m = 47   444
		"../UCI_dectrees/diabetes", // m = 10
		"../UCI_dectrees/linnerud", // m = 3   222
		"../UCI_dectrees/boston"	// m = 13
	};
	const int M_ARRAYS[7] = {7, 3, 12, 47, 10, 3, 13};

	uint32_t i = stoi(argv[1]);
	assert(i >= 0 && i <= 6);

	uint32_t M = M_ARRAYS[i];

	{
		const char *lastSlash = strrchr(filename[i], '/'); // Find the last slash
		string dataname = lastSlash ? string(lastSlash + 1) : string(filename[i]);
		cout << endl
			 << "DataSet: " << dataname << endl;
	}

#ifdef NON_INTERACTIVE_MODE
	cout << "======== Non-interactive scheme ========" << endl;
#else
	cout << "******** Interactive scheme ********" << endl;
#endif

	int Np = 13;
	DecTree tree;
	int length = (1 << Np) / M - 1;
	int PackTreeNum = 1;

	double servertime = 0.0;
	double csptime = 0.0;

	// gettimeofday(&time1, nullptr);
	// 1.1.1 Process the tree model to obtain an expanded tree model
	tree.read_from_file(filename[i]);
	tree.PackHiddenMod(length);

	// 1.1.2 Extract decision nodes, feature indices, and leaf node weights, and convert them into vectors
	// 1.1.2.1 Decision threshold
	vector<int64_t> y = encodeVector(tree.Extract_thresholds, M, 1 << Np);
	// cout << "Input model threshold" << endl;
	// print_vector(y, 24, 0);

	// 1.1.2.2 Feature selection index
	vector<int64_t> index = tree.Extract_attributes;

	// 1.1.2.3 Leaf node weights
	vector<int64_t> weight = tree.Extract_weights;

	// // 1.1.2.4 Flip status
	vector<int64_t> isSwap = encodeVector(tree.Extract_swapCondition, M, 1 << Np);

	// // 1.1.2.5 Real node status
	vector<int64_t> istrueNode = encodeVector(tree.Extract_trueNode, M, 1 << Np);

	// 1.1.2.6 Virtual node index
	vector<int64_t> structureIndex = tree.Extract_nodeIndex;

	// 1.1.3 The server initializes the cryptographic system and tree model parameters, encrypts the outsourced tree model parameters, and outsources the corresponding parameters

	gettimeofday(&time1, nullptr);
	Server server(Np, M, y, weight, index, istrueNode, isSwap);

	vector<Ciphertext> selectFeature;

	for (size_t i = 0; i < PackTreeNum; i++)
	{
		selectFeature.push_back(server.S_cipher);
	}

	gettimeofday(&time2, nullptr);

	printf("Unoptimized client (Server) initialization extra time: %fms\n", (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000);

	// 1.1.4 CSP initialization request
	gettimeofday(&time1, nullptr);
	CSP csp(Np, M, server.y_cipher, server.weight_cipher, selectFeature, server.True_index, server.public_key.get(), server.relin_keys.get(), server.gal_keys.get(), server.encryptor.get(), server.evaluator.get(), server.encoder.get());
	gettimeofday(&time2, nullptr);

	printf("Unoptimized server-side (CSP) initialization extra time: %fms\n", (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000);

	gettimeofday(&time1, nullptr);

	// 1.2.1 CSP initializes inference parameters in response to the client's request
	csp.csp_initial_system(PackTreeNum, structureIndex, true);

	gettimeofday(&time2, nullptr);
	csptime += (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000;

	// 1.2.2 Client-side encryption
	vector<int64_t> x;
	for (size_t i = 0; i < M; i++)
	{
		x.push_back(static_cast<int64_t>(random(1.0, 8000.0))); // Assume the range is from 1 to 8000.
	}

	Client client(Np, x, server.public_key.get(), server.encryptor.get(), server.evaluator.get(), server.encoder.get());

	// Select feature vectors
	vector<int64_t> selectvector;
	Plaintext selectvector_plain;
	for (size_t i = 0; i < length; i++)
	{
		selectvector.push_back(1);
	}
	selectvector = encodeVector(selectvector, M, 1 << Np);
	server.encoder->encode(selectvector, selectvector_plain);

	gettimeofday(&time1, nullptr);
	server.server_init_inference();
	gettimeofday(&time2, nullptr);

	cout << "Total initialization time for the client (Server): " << (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000 << "ms" << endl;

	cout << "Total initialization time for the server-side (CSP): " << csptime << "ms" << endl;

	// 2. Model inference
	// 2.1 Secure feature selection
	// 2.1.1 The client outsources the data, and the CSP begins feature selection
#ifdef NON_INTERACTIVE_MODE
	// 2.1.1 Non-interactive secure feature selection
	gettimeofday(&time1, nullptr);
	Ciphertext x_encrypted_1 = csp.csp_I_secure_feature_selection(client.x_cipher, 0);
	for (int i = 1; i < PackTreeNum; i++)
	{
		// cout << "Rotate " << i << "times" << endl;
		Ciphertext x_encrypted_2 = csp.csp_I_secure_feature_selection(client.x_cipher, i);
		csp.evaluator->multiply_plain_inplace(x_encrypted_2, selectvector_plain);
		csp.evaluator->rotate_rows(x_encrypted_2, -i, *csp.gal_keys, x_encrypted_2);
		csp.evaluator->add_inplace(x_encrypted_1, x_encrypted_2);
	}
	Ciphertext x_encrypted = x_encrypted_1;
	gettimeofday(&time2, nullptr);
	cout << "Feature selection time for the client (Server): " << 0 << "ms" << endl;

	double feature_choose_time = (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000;
	printf("Feature selection time for the server-side (CSP).: %fms\n", feature_choose_time);

#else
	gettimeofday(&time1, nullptr);
	// 2.1.2.1 Interactive secure feature selection
	Ciphertext *X_cipher = csp.csp_II_secure_feature_selection(client.x_cipher, PackTreeNum);
	gettimeofday(&time2, nullptr);
	double inter_cspt1 = (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000;

	// 2.1.2.2 The server decrypts and aggregates the perturbed data
	gettimeofday(&time1, nullptr);
	Ciphertext x_encrypted = server.server_secure_feature_selection(X_cipher, PackTreeNum);
	gettimeofday(&time2, nullptr);
	double inter_st1 = (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000;

	// 2.1.2.3 CSP removes the perturbation to obtain the ciphertext result
	gettimeofday(&time1, nullptr);
	x_encrypted = csp.csp_recover_selected_feature(x_encrypted);
	gettimeofday(&time2, nullptr);
	double inter_cspt2 = (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000;

	printf("Secure feature selection time for the client (Server): %fms\n", inter_st1);
	printf("Secure feature selection time for the server-side (CSP).: %fms\n", inter_cspt1 + inter_cspt2);

	double feature_choose_time = inter_st1 + inter_cspt1 + inter_cspt2;
#endif

	// 2.2 Secure comparison computation
	gettimeofday(&time1, nullptr);
	csp.evaluator->sub_inplace(x_encrypted, csp.y_cipher);
	x_encrypted = csp.csp_secure_compare(x_encrypted, csp.A_plain, csp.B_plain);
	gettimeofday(&time2, nullptr);
	double cmp_cspt1 = (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000;

	gettimeofday(&time1, nullptr);
	Ciphertext I1_encrypted = server.server_decrypt_compare_result(x_encrypted, true);
	gettimeofday(&time2, nullptr);
	double cmp_st1 = (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000;

	gettimeofday(&time1, nullptr);
	I1_encrypted = csp.csp_recover_vector(I1_encrypted, csp.R_cipher, csp.C1_cipher);
	gettimeofday(&time2, nullptr);
	double cmp_cspt2 = (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000;

	printf("Secure comparison time for the client (Server): %fms\n", cmp_st1);
	printf("Secure comparison time for the server-side (CSP): %fms\n", cmp_cspt1 + cmp_cspt2);

	double secure_compare_time = cmp_st1 + cmp_cspt1 + cmp_cspt2;

	// cout << "Decrypt to obtain the true prediction result I: " << endl;
	// print_vector(x, 24, 0);   // Display the integer with precision set to 0

	// 2.3 Path evaluation
	// 2.3.1 Perturbation of the true comparison result

	gettimeofday(&time1, nullptr);
	csp.evaluator->add_plain_inplace(I1_encrypted, csp.R1_plain);
	gettimeofday(&time2, nullptr);
	double eva_cspt1 = (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000;

	// 2.3.2 The server sends to the client, and the client computes the summation of the paths on the plaintext
	gettimeofday(&time1, nullptr);
	I1_encrypted = server.server_construct_path_sum(I1_encrypted, structureIndex);
	gettimeofday(&time2, nullptr);
	double eva_st1 = (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000;

	// 2.3.3 The client encrypts and sends to the server, the server decrypts, and uses the precomputed plaintext path to remove the mask, obtaining the true encrypted result
	gettimeofday(&time1, nullptr);
	csp.evaluator->add_plain_inplace(I1_encrypted, csp.cspPathSum_plain[0]);

	// 2.3.4 The server performs secure comparison computation to obtain the true positional result
	I1_encrypted = csp.csp_secure_compare(I1_encrypted, csp.A1_plain, csp.B1_plain);

	gettimeofday(&time2, nullptr);
	double eva_cspt2 = (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000;

	gettimeofday(&time1, nullptr);
	I1_encrypted = server.server_decrypt_compare_result(I1_encrypted, false);
	gettimeofday(&time2, nullptr);
	double eva_st2 = (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000;

	gettimeofday(&time1, nullptr);
	I1_encrypted = csp.csp_recover_vector(I1_encrypted, csp.R2_plain, csp.C2_plain);

	// 2.3.5 The server multiplies the final result by the weights, adds the T2 mask, and sends the sum of the encrypted result and the mask to the client
	I1_encrypted = csp.csp_calculate_weight(I1_encrypted, csp.T2_plain);
	gettimeofday(&time2, nullptr);
	double eva_cspt3 = (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000;

	gettimeofday(&time1, nullptr);
	// 2.3.6 The client performs decryption and removes the T2 mask
	Plaintext x_plain;
	server.decryptor->decrypt(I1_encrypted, x_plain);
	server.encoder->decode(x_plain, x);
	// cout << "The client decrypts to obtain the perturbed result comparison vector I2: " << endl;
	// print_vector(x, 24, 0);   // Display the integer with precision set to 0

	int64_t result = 0;
	for (size_t i = 0; i < server.poly_modulus_degree; i++)
	{
		result += x[i];
	}
	result -= csp.T2sum;
	gettimeofday(&time2, nullptr);
	double eva_st3 = (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000;

	printf("Path evaluation time for the client (Server): %fms\n", eva_st1 + eva_st2 + eva_st3);
	printf("Path evaluation time for the server-side (CSP): %fms\n", eva_cspt1 + eva_cspt2 + eva_cspt3);

	double eva_time = eva_st1 + eva_st2 + eva_st3 + eva_cspt1 + eva_cspt2 + eva_cspt3;

	printf("Total online overhead time is %fms\n", feature_choose_time + secure_compare_time + eva_time);

	return 0;
}