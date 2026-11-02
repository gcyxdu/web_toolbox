#include <seal/seal.h>
#include <sys/time.h>
#include <iostream>
#include "examples.h"
#include <chrono>
#include <ctime> // include time()
#include <cmath>
#include <vector>
#include <unordered_map>
#include <cassert>
#include "BFSdectree.hpp"
#include <sstream>
#include <arpa/inet.h>
#include <unistd.h>

using namespace seal;
using namespace std;

struct timeval time1, time2;
float timeuse;

double random(double start, double end)
{
	return start + (end - start) * rand() / (RAND_MAX + 1.0);
}

int random(int min, int max)
{
	static std::random_device rd; // Obtain the random seed
	// static std::mt19937 generator(rd());                       // Generate random numbers using the Mersenne Twister algorithm
	std::mt19937 generator(1234);
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
			std::cout << ", Left Weight: " << node->left_weight
					  << ", Right Weight: " << node->right_weight << std::endl;
			printTree(node->left);
			printTree(node->right);
		}
	}

	void sumPaths(int64_t weight, TreeNode *node, int current_sum)
	{
		if (node == nullptr)
		{
			cout << "1 ";
			return;
		}

		// Update the sum of the current path
		current_sum += weight;

		// If a leaf node is reached, print the sum of the current path
		if (node->left == nullptr && node->right == nullptr)
		{
			sumweight.push_back(current_sum + node->left_weight);
			sumweight.push_back(current_sum + node->right_weight);
		}
		else if (node->left == nullptr)
		{
			sumweight.push_back(current_sum + node->left_weight);
			sumPaths(node->right_weight, node->right, current_sum); // Recursively traverse the right subtree
		}
		else if (node->right == nullptr)
		{
			sumPaths(node->left_weight, node->left, current_sum); // Recursively traverse the left subtree
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

		int number = 1;
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
				number++;
			}
			if (nodes.find(rightIndex) != nodes.end())
			{
				currentNode->right = nodes[rightIndex];
				number++;
			}
		}

		// cout << "number: " << number << endl;

		// Return the root node, assuming the root node's index is 1
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

		// Return to the root node, assuming the root node has an index of 1
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
	// print_vector(tree.sumweight, 24, 0);

	return tree.sumweight;
}

void testPathSumCorrect()
{
	vector<int64_t> compareBit = {0, 0, 1, 1, 1, 1, 0};
	vector<int64_t> randomBit = {10, 20, 11, 41, 81, 2, 3};
	std::vector<int64_t> result(compareBit.size());

	// Element-wise addition.
	for (size_t i = 0; i < compareBit.size(); ++i)
	{
		result[i] = compareBit[i] + randomBit[i];
	}
	vector<int64_t> structures = {1, 2, 3, 6, 7, 12, 13};
	vector<int64_t> aa = testTreeSumPath(randomBit, false, structures);
	vector<int64_t> bb = testTreeSumPath(result, true, structures);
	vector<int64_t> cc = testTreeSumPath(compareBit, true, structures);

	for (size_t i = 0; i < compareBit.size(); i++)
	{
		if (aa[i] + bb[i] != cc[i])
		{
			cout << "PathSum is false" << endl;
			return;
		}
	}
	cout << "PathSum is true" << endl;
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

class Server
{
public:
	// The key parameters required by the server
	const PublicKey *public_key;
	const RelinKeys *relin_keys;
	const GaloisKeys *gal_keys;
	const Encryptor *encryptor;
	const Evaluator *evaluator;
	unique_ptr<BatchEncoder> encoder;
	size_t poly_modulus_degree;

	// Feature dimension and the total number of decision nodes
	int M, decNodeNumber;

	// Node flipping situation
	vector<int64_t> isSwap, istrueNode, y;

	int64_t T2sum = 0, lengthPath;

	// Server model parameters: y represents the split threshold for each node, weight represents the leaf node weights, and S represents the feature selection positions
	Plaintext y_plain, weight_plain;

	// Parameters generated during the first secure comparison
	Plaintext A_plain, B_plain, R_plain, C1_plain, R1_plain, Extract_R1_plain;

	// Parameters generated during the second secure comparison
	Plaintext A1_plain, B1_plain, R2_plain, C2_plain;

	// Server path summation results and masks
	vector<Plaintext> Random_plain, SeverPathSum_plain, S_plain;
	Plaintext T2_plain, Random_sum_plain;

	Server(int Np, int M, vector<int64_t> Node_y, vector<int64_t> weight, vector<int64_t> index, vector<int64_t> istrueNode, vector<int64_t> isSwap)
	{
		EncryptionParameters parms(scheme_type::bfv);
		poly_modulus_degree = 1 << Np;
		parms.set_poly_modulus_degree(poly_modulus_degree);
		parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
		// parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {30, 30, 30}));
		parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 50)); // Set an appropriate plaintext modulus

		// 1. Initialize SEALContext
		shared_ptr<SEALContext> context = make_shared<SEALContext>(parms);

		// 2. Initialize the encoder
		encoder = make_unique<BatchEncoder>(*context);

		y = Node_y;
		this->istrueNode = istrueNode;
		this->isSwap = isSwap;

		this->M = M;
		this->decNodeNumber = index.size();

		// 4. Extract the feature index vector
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
		// 5. The encoder, decision node thresholds, weights, and feature indices can be reused
		encoder->encode(y, y_plain);
		encoder->encode(weight, weight_plain);
		Plaintext temp;
		encoder->encode(S, temp);
		S_plain.push_back(temp);
	}

	// The constructor uses pointers instead of directly copying objects
	void server_initial_cryptosystem(const PublicKey *public_key, const RelinKeys *relin_keys, const GaloisKeys *gal_keys,
									 const Encryptor *encryptor, const Evaluator *evaluator)
	{
		this->public_key = public_key;
		this->relin_keys = relin_keys;
		this->gal_keys = gal_keys;
		this->encryptor = encryptor;
		this->evaluator = evaluator;
	}

	void server_initial_system(vector<int64_t> structureIndex, int PackTreeNum, bool ifInteractive)
	{
		//  The constructor uses pointers instead of directly copying objects
		vector<int64_t> A, B, R, C1, R1;
		//  Here, the parameters are generated for the second secure comparison
		vector<int64_t> A1, B1, R2, C2;
		vector<int64_t> Extract_R1, T2, RandomSum;

		// 1. The server generates parameters related to the first secure comparison
		int temp = 0;
		for (size_t i = 0; i < poly_modulus_degree; i++)
		{
			A.push_back(static_cast<int64_t>(random(1.0, 100.0)));
			B.push_back(A.back() - static_cast<int64_t>(random(1.0, A.back())));
			R.push_back(random(0, 10000) >= 5000 ? -1 : 1);
			// C1.push_back(R.back() == -1 ? 1 : 0);
			C1.push_back(0);
			R1.push_back(static_cast<int64_t>(random(1.0, 1000.0)));
			T2.push_back(random(0, 1000)); // The mask vector for path evaluation
			RandomSum.push_back(0);		   // The summation mask for feature selection
			T2sum += T2[i];				   // The summation mask for path evaluation
		}

		for (size_t i = 0; i < PackTreeNum; i++)
		{
			// 2.1 Extract the corresponding vector
			Extract_R1 = Extract_vector(R1, i, decNodeNumber, M);

			// 2.2 The server sums the masked paths
			vector<int64_t> SeverPathSum = testTreeSumPath(Extract_R1, false, structureIndex);
			lengthPath = SeverPathSum.size();

			// 2.3 The server encodes the masks
			Plaintext temp;
			encoder->encode(SeverPathSum, temp);
			SeverPathSum_plain.push_back(temp);

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

		T2sum = 0;
		for (size_t i = 0; i < lengthPath; i++)
		{
			T2sum += T2[i];
		}

		if (ifInteractive)
		{
			encoder->encode(RandomSum, Random_sum_plain);
		}

		for (size_t i = 0; i < poly_modulus_degree; i++)
		{
			// Parameters required for the second secure comparison: Mask all paths, including virtual paths, to protect the tree structure
			A1.push_back(static_cast<int64_t>(random(1.0, 100.0)));
			B1.push_back(A1.back() - static_cast<int64_t>(random(1.0, A1.back())));
			R2.push_back(random(0, 10000) >= 5000 ? -1 : 1);
			C2.push_back(R2.back() == -1 ? 1 : 0);
		}

		// Precompute BR - ARY
		for (size_t i = 0; i < poly_modulus_degree; i++)
		{
			A[i] *= R[i];			   // Calculate AR
			B[i] *= R[i];			   // Calculate BR
			B[i] = B[i] - A[i] * y[i]; // Calculate BR - ARY
		}

		// Pre-update
		for (size_t i = 0; i < poly_modulus_degree; i++)
		{
			R[i] *= isSwap[i];
			if (istrueNode[i] == 0)
			{
				R[i] = 0;
			}
			// if(R[i] == 1 || (R[i] == 0 && isSwap[i] == 1)) C1[i] = 0;
			if ((istrueNode[i] == 1 && R[i] == -1) || (istrueNode[i] == 0 && isSwap[i] == -1))
			{
				C1[i] = 1;
			}
		}

		// // Pre-update
		// for (size_t i = 0; i < poly_modulus_degree; i++)
		// {
		//     if(R[i] == -1){
		//         C1[i] = 1;
		//     }
		// }

		for (size_t i = 0; i < poly_modulus_degree; i++)
		{
			A1[i] *= (-R2[i]); // Calculate AR
			B1[i] *= R2[i];	   // Calculate BR
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

	Ciphertext server_I_secure_feature_selection(Ciphertext x_encrypted, int index)
	{
		evaluator->multiply_plain_inplace(x_encrypted, S_plain[index]);
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

	Ciphertext *server_II_secure_feature_selection(Ciphertext x_cipher, int PackTreeNum)
	{
		Ciphertext *result = new Ciphertext[PackTreeNum];
		;
		for (size_t i = 0; i < PackTreeNum; i++)
		{
			evaluator->multiply_plain(x_cipher, S_plain[i], result[i]);
			evaluator->add_plain_inplace(result[i], Random_plain[i]);
		}
		return result;
	}

	Ciphertext server_recover_selected_feature(Ciphertext x_cipher)
	{
		evaluator->add_plain_inplace(x_cipher, Random_sum_plain);
		return x_cipher;
	}

	Ciphertext server_secure_compare(Ciphertext x_encrypted, Plaintext A_plain, Plaintext B_plain)
	{
		// 1. Perturb the difference: X*AR - BR - YAR
		evaluator->multiply_plain_inplace(x_encrypted, A_plain);
		evaluator->add_plain_inplace(x_encrypted, B_plain);
		return x_encrypted;
	}

	Ciphertext server_recover_vector(Ciphertext I1_encrypted, Plaintext R_plain, Plaintext C1_plain)
	{
		// 1. The server recovers the comparison result vector
		evaluator->multiply_plain_inplace(I1_encrypted, R_plain);
		evaluator->add_plain_inplace(I1_encrypted, C1_plain);

		return I1_encrypted;
	}

	Ciphertext server_calculate_weight(Ciphertext I1_encrypted, Plaintext T2_plain)
	{
		evaluator->multiply_plain_inplace(I1_encrypted, weight_plain);
		evaluator->add_plain_inplace(I1_encrypted, T2_plain);
		return I1_encrypted;
	}
};

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

vector<int64_t> extractVector(vector<int64_t> x, int M)
{
	vector<int64_t> result;
	for (size_t i = 0; i < x.size(); i++)
	{
		if (i % M == 0)
		{
			result.push_back(x[i]);
		}
	}
	return result;
}

vector<int64_t> plainReLU(vector<int64_t> x, vector<int64_t> y)
{
	vector<int64_t> result;
	for (size_t i = 0; i < x.size(); i++)
	{
		if (x[i] - y[i] < 0)
		{
			result.push_back(0);
		}
		else
		{
			result.push_back(1);
		}
	}
	return result;
}

vector<int64_t> recoverPlainReLU(vector<int64_t> x, vector<int64_t> Extract_trueNode, vector<int64_t> Extract_swapCondition)
{
	for (size_t i = 0; i < Extract_trueNode.size(); i++)
	{
		if (Extract_trueNode[i] == 0 && Extract_swapCondition[i] == -1)
		{
			x[i] = 1;
		}
		else if (Extract_trueNode[i] == 0 && Extract_swapCondition[i] == 1)
		{
			x[i] = 0;
		}
		else if (Extract_trueNode[i] == 1 && Extract_swapCondition[i] == -1)
		{
			x[i] = 1 - x[i];
		}
	}
	return x;
}

// The function calculates a path from the root node to the result
vector<int64_t> calculatePath(const vector<int64_t> &node_index, const vector<int64_t> &x)
{
	vector<int64_t> path;			 // The path of the current node
	int64_t current = node_index[0]; // Start from the root node
	path.push_back(current);		 // Add the root node to the path

	for (size_t i = 0; i < x.size(); ++i)
	{
		// Select the next node based on the x value

		if (node_index[i] == current)
		{
			if (x[i] == 0)
			{
				current = 2 * current; // Move to the left child node
			}
			else
			{
				current = 2 * current + 1; // Move to the right child node
			}
			// If the current node does not exist in node_index, stop
			if (find(node_index.begin(), node_index.end(), current) == node_index.end())
			{
				break;
			}

			path.push_back(current); // Record the current node
		}
	}

	return path;
}


// int main() {
//     // Network Settings
//     int server_fd = socket(AF_INET, SOCK_STREAM, 0);
//     sockaddr_in address{};
//     address.sin_family = AF_INET;
//     address.sin_addr.s_addr = INADDR_ANY;
//     address.sin_port = htons(8080);

//     bind(server_fd, (sockaddr*)&address, sizeof(address));
//     listen(server_fd, 1);
//     int client_fd = accept(server_fd, nullptr, nullptr);

//     // Receive length
//     uint32_t len;
//     recv(client_fd, &len, sizeof(len), 0);

//     // Receive ciphertext content
//     std::vector<char> buffer(len);
//     size_t received = 0;
//     while (received < len) {
//         ssize_t bytes = recv(client_fd, buffer.data() + received, len - received, 0);
//         if (bytes <= 0) break;
//         received += bytes;
//     }

//     // Deserialize ciphertext
//     std::stringstream stream(std::string(buffer.begin(), buffer.end()));
//     EncryptionParameters parms(scheme_type::ckks);
//     parms.set_poly_modulus_degree(8192);
//     parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 40, 60}));
//     SEALContext context(parms);

//     Ciphertext encrypted;
//     encrypted.load(context, stream);
//     std::cout << "Encrypted ciphertext received and loaded." << std::endl;

//     close(client_fd);
//     close(server_fd);
//     return 0;
// }

// void receive_stream(int socket, std::stringstream &stream) {
//     uint32_t size;
//     recv(socket, &size, sizeof(size), 0);
//     std::vector<char> buffer(size);
//     recv(socket, buffer.data(), size, 0);
//     stream.write(buffer.data(), size);
// }

// receive_stream
void receive_stream(int sock, std::stringstream &stream) {
    size_t size;

    // 1. Collect size first
    recv(sock, &size, sizeof(size), MSG_WAITALL);

    // 2. Receiving Data
    std::vector<char> buffer(size);
    recv(sock, buffer.data(), size, MSG_WAITALL);

    // 3. Fill in the stream
    stream.str(std::string(buffer.begin(), buffer.end()));
}

// send_stream
void send_stream(int sock, std::stringstream &stream) {
    std::string data = stream.str();
    size_t size = data.size();

    // 1. Starting size
    send(sock, &size, sizeof(size), 0);

    // 2. Repost content
    send(sock, data.data(), size, 0);
}

void send_ciphertext(int sock, const Ciphertext &cipher) {
    std::stringstream ss;
    cipher.save(ss);
    send_stream(sock, ss);
}

void receive_ciphertext(int sock, Ciphertext &cipher, const SEALContext &context) {
    std::stringstream ss;
    receive_stream(sock, ss);
    cipher.load(context, ss);
}

void send_vector_int64(int sock, const std::vector<int64_t> &vec) {
    std::stringstream ss;
    size_t size = vec.size();
    ss.write(reinterpret_cast<const char*>(&size), sizeof(size));
    for (auto val : vec) {
        ss.write(reinterpret_cast<const char*>(&val), sizeof(int64_t));
    }
    send_stream(sock, ss);
}

void send_int64_values(int sock, const std::vector<int64_t>& values) {
    std::stringstream ss;
    size_t count = values.size();
    ss.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (int64_t val : values) {
        ss.write(reinterpret_cast<const char*>(&val), sizeof(int64_t));
    }
    send_stream(sock, ss);
}


int main() {
    // 0.1. Socket init
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(5000);
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 1);
    int addrlen = sizeof(address);
    int client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);

    // 0.2. Receive SEAL keys
    std::stringstream pk_stream, relin_stream, gal_stream;
    receive_stream(client_socket, pk_stream);
    receive_stream(client_socket, relin_stream);
    receive_stream(client_socket, gal_stream);

    // 0.3. Setup encryption context (same as client)
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 1 << 13;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 50));
    SEALContext context(parms);
    BatchEncoder encoder(context);

    // 0.4. Load keys using context
    PublicKey public_key;
    public_key.load(context, pk_stream);

    RelinKeys relin_keys;
    relin_keys.load(context, relin_stream);

    GaloisKeys gal_keys;
    gal_keys.load(context, gal_stream);

	Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);


    std::cout << "Server: Keys received and loaded successfully." << std::endl;

	// 1.1 The server reads the tree model
	const char *filename[7] = {
		"../UCI_dectrees/wine",		// i = 0; M = 7
		"../UCI_dectrees/iris",		// i = 1; M = 3
		"../UCI_dectrees/breast",	// i = 2; M = 12
		"../UCI_dectrees/digits",	// i = 3; M = 47
		"../UCI_dectrees/diabetes", // i = 4; M = 10
		"../UCI_dectrees/linnerud", // i = 5; M = 3
		"../UCI_dectrees/boston"	// i = 6; M = 13
	};
	const int M_ARRAYS[7] = {7, 3, 12, 47, 10, 3, 13};

	uint32_t i = 0;

	uint32_t M = M_ARRAYS[i];



    int Np = 13;
	DecTree tree;
	int length = (1 << Np) / M - 1;
	int PackTreeNum = 1;

	double servertime = 0.0;
	double clienttime = 0.0;

	vector<int64_t> x; // Use integer vectors
	x.reserve(1 << Np);

	for (size_t i = 0; i < M; i++)
	{
		x.push_back(static_cast<int64_t>(random(1.0, 1000.0))); // Assume the range is from 1 to 1000
	}

	// 1.1.1 Process the tree model to obtain an expanded tree model
	tree.read_from_file(filename[i], x);
	tree.PackHiddenMod(length);
	// tree.OutputModel();

	// 1.1.2 Extract decision nodes, feature indices, and leaf node weights, and convert them into vectors
	// 1.1.2.1 Decision threshold
	vector<int64_t> y = encodeVector(tree.Extract_thresholds, M, 1 << Np);

	// 1.1.2.2 Feature selection index
	vector<int64_t> index = tree.Extract_attributes;

	// 1.1.2.3 Leaf node weights
	vector<int64_t> weight = tree.Extract_weights;

	// 1.1.2.4 Flipping situation
	vector<int64_t> isSwap = encodeVector(tree.Extract_swapCondition, M, 1 << Np);

	// 1.1.2.5 Real node situation
	vector<int64_t> istrueNode = encodeVector(tree.Extract_trueNode, M, 1 << Np);

	// 1.1.2.6 Virtual node index
	vector<int64_t> structureIndex = tree.Extract_nodeIndex;

	// 1.1.3 The server builds the encoder and reuses the tree model parameters
	Server server(Np, M, y, weight, index, istrueNode, isSwap);
	// Here, feature selection is performed for multiple models
	for (size_t i = 0; i < PackTreeNum - 1; i++)
	{
		server.S_plain.push_back(server.S_plain[0]);
	}

	// 1.2.1 The server formally initializes the system to respond to each client's request
	server.server_initial_system(structureIndex, PackTreeNum, true);

	// 1.2.4 The client establishes a connection with the server and sends encrypted system parameters to the server
	server.server_initial_cryptosystem(&public_key, &relin_keys, &gal_keys,
									   &encryptor, &evaluator);

	// 1.2.5 Select the feature vector
	vector<int64_t> selectvector;
	Plaintext selectvector_plain;
	for (size_t i = 0; i < length; i++)
	{
		selectvector.push_back(1);
	}
	selectvector = encodeVector(selectvector, M, 1 << Np);
	server.encoder->encode(selectvector, selectvector_plain);

	// 1.2.6 send model structureIndex
	send_vector_int64(client_socket, structureIndex);
	
	// 2. Model inference
	Ciphertext x_encrypted;

	// 2.1.2 recieve client's vector
	receive_ciphertext(client_socket, x_encrypted, context);

	// 2.2.1 Secure feature selection
	// 2.2.1.1 Non-interactive secure feature selection
	Ciphertext x_encrypted_1 = server.server_I_secure_feature_selection(x_encrypted, 0);
	for (int i = 1; i < PackTreeNum; i++)
	{
		cout << "Rotate" << i << "times" << endl;
		Ciphertext x_encrypted_2 = server.server_I_secure_feature_selection(x_encrypted, i);
		server.evaluator->multiply_plain_inplace(x_encrypted_2, selectvector_plain);
		server.evaluator->rotate_rows(x_encrypted_2, -i, *server.gal_keys, x_encrypted_2);
		server.evaluator->add_inplace(x_encrypted_1, x_encrypted_2);
	}

	// 2.3 Oblivious comparison
	x_encrypted = x_encrypted_1;
	// 2.3.1 a(x-y)+b
	x_encrypted = server.server_secure_compare(x_encrypted, server.A_plain, server.B_plain);

	// 2.3.2.1 send a(x-y)+b
	send_ciphertext(client_socket, x_encrypted);  // send to client

	// 2.3.4.1 recieve ciphertext
	Ciphertext I1_encrypted;
	receive_ciphertext(client_socket, I1_encrypted, context);
	I1_encrypted = server.server_recover_vector(I1_encrypted, server.R_plain, server.C1_plain);

	// 2.4 Path evaluation
	// 2.4.1 Perturb the real comparison result
	server.evaluator->add_plain_inplace(I1_encrypted, server.SeverPathSum_plain[0]);

	// 2.4.2.1 send ciphertext
	send_ciphertext(client_socket, I1_encrypted);  // send to client

	// 2.4.2.4 recieve result
	receive_ciphertext(client_socket, I1_encrypted, context);

	// 2.4.3 The client encrypts and sends to the server; the server decrypts and uses the precomputed plaintext paths to eliminate the masks, obtaining the real encrypted result
	server.evaluator->add_plain_inplace(I1_encrypted, server.SeverPathSum_plain[0]);

	// 2.4.4 The server performs secure comparison calculations to obtain the real position result
	I1_encrypted = server.server_secure_compare(I1_encrypted, server.A1_plain, server.B1_plain);
	
	// 2.4.4.1
	send_ciphertext(client_socket, I1_encrypted);  // send to client

	// 2.4.5.2
	receive_ciphertext(client_socket, I1_encrypted, context);

	I1_encrypted = server.server_recover_vector(I1_encrypted, server.R2_plain, server.C2_plain);

	// 2.4.6 The server multiplies the final result by the weights, adds the T2 mask, and sends the encrypted result and the summation result of the masks to the client
	x_encrypted = server.server_calculate_weight(x_encrypted, server.T2_plain);

	// 2.5 Client obtains the final result
	send_ciphertext(client_socket, x_encrypted);
	send_int64_values(client_socket, {server.lengthPath, server.T2sum});



    close(client_socket);
    close(server_fd);
    return 0;
}