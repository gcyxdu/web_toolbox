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
using namespace std::chrono;

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



class Client
{
public:
	// The key parameters required by the client
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

	// The dimensionality of the client's feature vector
	int M;

	Plaintext plain_0;
	Ciphertext cipher0_1, cipher0_2, cipher0_3;

	// Constructor
	Client(int Np)
	{
		client_initial_keys(Np);
	}

	void client_initial_keys(int Np)
	{
		EncryptionParameters parms(scheme_type::bfv);
		poly_modulus_degree = 1 << Np;
		parms.set_poly_modulus_degree(poly_modulus_degree);
		parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
		// parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {30, 30, 30}));
		parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 50)); // Set an appropriate plaintext modulus

		// Initialize SEALContext
		context = make_shared<SEALContext>(parms);

		// Initialize KeyGenerator, Encryptor, Evaluator, Decryptor, and Encoder.
		keygen = make_unique<KeyGenerator>(*context);
		public_key = make_unique<PublicKey>();
		keygen->create_public_key(*public_key);

		relin_keys = make_unique<RelinKeys>();
		keygen->create_relin_keys(*relin_keys);

		gal_keys = make_unique<GaloisKeys>();
		keygen->create_galois_keys(*gal_keys); // BFV scheme may not require Galois keys

		encryptor = make_unique<Encryptor>(*context, *public_key);
		evaluator = make_unique<Evaluator>(*context);
		decryptor = make_unique<Decryptor>(*context, keygen->secret_key());
		encoder = make_unique<BatchEncoder>(*context);
	}

	Ciphertext client_Load_vector(int M_size, vector<int64_t> x)
	{
		M = M_size;
		Plaintext x_plain;

		// Here, repeatedly expand the X vector to fill the entire vector
		int j = 0;
		for (size_t i = M; i < poly_modulus_degree; i++)
		{
			x.push_back(x[j]);
			j = (j + 1) % M;
		}
		encoder->encode(x, x_plain); // Use the integer encoder
		Ciphertext x_encrypted;
		encryptor->encrypt(x_plain, x_encrypted);

		vector<int64_t> zero_vector;
		for (size_t i = 0; i < poly_modulus_degree; i++)
		{
			zero_vector.push_back(0);
		}
		encoder->encode(zero_vector, plain_0);
		encryptor->encrypt(plain_0, cipher0_1);
		encryptor->encrypt(plain_0, cipher0_2);
		encryptor->encrypt(plain_0, cipher0_3);

		return x_encrypted;
	}

	Ciphertext client_secure_feature_selection(Ciphertext *x_encrypt, int PackTreeNum)
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
		// encryptor->encrypt(x_plain, x_cipher);

		return x_cipher;
	}

	// When sign is true, it is the first comparison; otherwise, it is the second comparison.
	Ciphertext client_decrypt_compare_result(Ciphertext x_encrypted, bool sign)
	{
		Plaintext x_plain;
		vector<int64_t> x;

		decryptor->decrypt(x_encrypted, x_plain);
		encoder->decode(x_plain, x);
		// cout << "Output the client's vector AR * (X - Y) + BR";
		// print_vector(x, 24, 0);

		vector<int64_t> I1;
		I1.reserve(poly_modulus_degree);
		if (sign)
		{
			for (size_t i = 0; i < poly_modulus_degree; i++)
			{
				if (x[i] < 0 && i % M == 0)
				{
					I1.push_back(0);
				}
				else
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
		// print_vector(I1, 24, 0);

		Plaintext I1_plain;
		encoder->encode(I1, I1_plain);
		Ciphertext I1_encrypted;
		evaluator->add_plain(cipher0_2, I1_plain, I1_encrypted);
		// encryptor->encrypt(I1_plain, I1_encrypted);

		return I1_encrypted;
	}

	Ciphertext client_construct_path_sum(Ciphertext I1_encrypted, int length, vector<int64_t> structureIndex)
	{
		Plaintext x_plain;
		vector<int64_t> x;
		decryptor->decrypt(I1_encrypted, x_plain);
		encoder->decode(x_plain, x);

		vector<int64_t> Extract_x;
		for (size_t i = 0; i < poly_modulus_degree; i++)
		{
			if ((i % M == 0) && (Extract_x.size() < length))
			{
				Extract_x.push_back(x[i]);
			}
		}

		vector<int64_t> ClientPathSum = testTreeSumPath(Extract_x, true, structureIndex);

		Plaintext ClientPathSum_plain;
		encoder->encode(ClientPathSum, ClientPathSum_plain);
		evaluator->add_plain(cipher0_3, ClientPathSum_plain, I1_encrypted);
		// encryptor->encrypt(ClientPathSum_plain, I1_encrypted);

		return I1_encrypted;
	}
};

vector<int64_t> Extract_vector(vector<int64_t> a, int index, int length, int dim)
{
	vector<int64_t> result;
	for (size_t i = 0; i < length; i++)
	{
		result.push_back(a[i * dim + index]);
	}
	return result;
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
//     int sock = socket(AF_INET, SOCK_STREAM, 0);
//     sockaddr_in serv_addr{};
//     serv_addr.sin_family = AF_INET;
//     serv_addr.sin_port = htons(8080);
//     inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
//     connect(sock, (sockaddr*)&serv_addr, sizeof(serv_addr));

//     // CKKS setup
//     EncryptionParameters parms(scheme_type::ckks);
//     size_t poly_modulus_degree = 8192;
//     parms.set_poly_modulus_degree(poly_modulus_degree);
//     parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
//     SEALContext context(parms);

//     KeyGenerator keygen(context);
//     PublicKey public_key;
//     keygen.create_public_key(public_key);
//     Encryptor encryptor(context, public_key);
//     CKKSEncoder encoder(context);

//     double scale = pow(2.0, 40);
//     Plaintext plain;
//     encoder.encode(3.14159, scale, plain);

//     Ciphertext encrypted;
//     encryptor.encrypt(plain, encrypted);

//     // Serialized ciphertext
//     std::stringstream stream;
//     encrypted.save(stream);
//     std::string payload = stream.str();

//     // Send length + content
//     uint32_t len = payload.size();
//     send(sock, &len, sizeof(len), 0);
//     send(sock, payload.data(), payload.size(), 0);

//     std::cout << "Encrypted data sent (" << len << " bytes)." << std::endl;
//     close(sock);
//     return 0;
// }

// void send_stream(int socket, std::stringstream &stream) {
//     std::string str = stream.str();
//     uint32_t size = str.size();
//     send(socket, &size, sizeof(size), 0);
//     send(socket, str.data(), size, 0);
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




// int main() {
//     // 1. BFV setup
//     EncryptionParameters parms(scheme_type::bfv);
//     size_t poly_modulus_degree = 1 << 13;
//     parms.set_poly_modulus_degree(poly_modulus_degree);
//     parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
//     // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {30, 30, 30}));
//     parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 50)); // Set an appropriate plaintext modulus

//     SEALContext context(parms);
//     BatchEncoder encoder(context);

//     KeyGenerator keygen(context);
//     auto secret_key = keygen.secret_key();
//     PublicKey public_key;
//     keygen.create_public_key(public_key);
//     RelinKeys relin_keys;
//     keygen.create_relin_keys(relin_keys);
//     GaloisKeys gal_keys;
//     keygen.create_galois_keys(gal_keys);
                        

//     // 2. Serialize keys
//     std::stringstream pk_stream, relin_stream, gal_stream;
//     public_key.save(pk_stream);
//     relin_keys.save(relin_stream);
//     gal_keys.save(gal_stream);

//     // 3. Connect to server
//     int sock = socket(AF_INET, SOCK_STREAM, 0);
//     sockaddr_in serv_addr{};
//     serv_addr.sin_family = AF_INET;
//     serv_addr.sin_port = htons(8080);
//     inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
//     connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

//     // 4. Send streams
//     send_stream(sock, pk_stream);
//     send_stream(sock, relin_stream);
//     send_stream(sock, gal_stream);

//     std::cout << "Client: Keys sent successfully." << std::endl;



//     close(sock);
//     return 0;
// }


std::vector<int64_t> receive_vector_int64(int sock) {
    std::stringstream ss;
    receive_stream(sock, ss);

    size_t size;
    ss.read(reinterpret_cast<char*>(&size), sizeof(size));
    std::vector<int64_t> vec(size);
    for (size_t i = 0; i < size; ++i) {
        ss.read(reinterpret_cast<char*>(&vec[i]), sizeof(int64_t));
    }
    return vec;
}

std::vector<int64_t> receive_int64_values(int sock) {
    std::stringstream ss;
    receive_stream(sock, ss);

    size_t count;
    ss.read(reinterpret_cast<char*>(&count), sizeof(count));
    std::vector<int64_t> values(count);
    for (size_t i = 0; i < count; ++i) {
        ss.read(reinterpret_cast<char*>(&values[i]), sizeof(int64_t));
    }
    return values;
}


int main() {
    // 0.1. Initialize Client (key automatically created)
	int Np =13;
    Client client(Np); // 2^13 = 8192

	const int M_ARRAYS[7] = {7, 3, 12, 47, 10, 3, 13};

	uint32_t i = 6;

	uint32_t M = M_ARRAYS[i];
	// uint32_t M = 30;

	int length = (1 << Np) / M - 1;
    
	// 0.2. Create a key stream
    std::stringstream pk_stream, relin_stream, gal_stream;
    client.public_key->save(pk_stream);
    client.relin_keys->save(relin_stream);
    client.gal_keys->save(gal_stream);

    std::cout << "Client: public_key size: " << pk_stream.str().size() << std::endl;
    std::cout << "Client: relin_keys size: " << relin_stream.str().size() << std::endl;
    std::cout << "Client: gal_keys size: " << gal_stream.str().size() << std::endl;

    // 0.3. Connect to server
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(5000);
    inet_pton(AF_INET, "8.139.254.165", &serv_addr.sin_addr);
    connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    // 0.4. Send keys
    send_stream(sock, pk_stream);
    send_stream(sock, relin_stream);
    send_stream(sock, gal_stream);

    std::cout << "Client: Keys sent successfully." << std::endl;

	vector<int64_t> x; // Use integer vectors
	x.reserve(1 << Np);

	for (size_t i = 0; i < M; i++)
	{
		x.push_back(static_cast<int64_t>(random(1.0, 1000.0))); // Assume the range is from 1 to 1000
	}

	Ciphertext x_encrypted = client.client_Load_vector(M, x);

	// 1.2.6 recieve model structureIndex
	std::vector<int64_t> structureIndex = receive_vector_int64(sock);

	// 2. Model inference
	// 2.1.1 Send ciphertext
	auto start = high_resolution_clock::now();

	send_ciphertext(sock, x_encrypted);

	// 2.3.2.1 recieve a(x-y)+b
	receive_ciphertext(sock, x_encrypted, *client.context);

	// 2.3.3 client_decrypt_compare_result
	Ciphertext I1_encrypted = client.client_decrypt_compare_result(x_encrypted, true);

	// 2.3.4.1 Send ciphertext
	send_ciphertext(sock, I1_encrypted);

	// 2.4 Path evaluation
	// 2.4.2.2 The server sends to the client, and the client calculates the summation of the paths in plaintext
	receive_ciphertext(sock, I1_encrypted, *client.context);
	I1_encrypted = client.client_construct_path_sum(I1_encrypted, length, structureIndex);
    
	// 2.4.2.3 return result
	send_ciphertext(sock, I1_encrypted);

	// 2.4.4.2
	receive_ciphertext(sock, I1_encrypted, *client.context);

	// 2.4.5
	I1_encrypted = client.client_decrypt_compare_result(I1_encrypted, false);

	// 2.4.5.1
	send_ciphertext(sock, I1_encrypted);

	// 2.5 recieve the ciphertext and obtain the final result
	receive_ciphertext(sock, I1_encrypted, *client.context);

    auto end = high_resolution_clock::now(); 
    auto micros = duration_cast<microseconds>(end - start);
    std::cout << "Running Time:" << micros.count() << " us" << std::endl;

	std::vector<int64_t> received = receive_int64_values(sock);
	int64_t lengthPath = received[0];
	int64_t T2sum = received[1];

	// 2.5.1 decrypt the result
	Plaintext result_plain;
	client.decryptor->decrypt(I1_encrypted, result_plain);
	vector<int64_t> result_vec;
	client.encoder->decode(result_plain, result_vec);

	int64_t final_result = accumulate(result_vec.begin(), result_vec.begin() + lengthPath, 0LL) - T2sum;

    close(sock);
    return 0;
}
