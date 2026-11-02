/**
 \file 		dectree.hpp
 \author 	kiss@encrypto.cs.tu-darmstadt.de
 \copyright	Decision Tree
			Copyright (C) 2019 Cryptography and Privacy Engineering Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
			it under the terms of the GNU Affero General Public License as published
			by the Free Software Foundation, either version 3 of the License, or
			(at your option) any later version.
			This program is distributed in the hope that it will be useful,
			but WITHOUT ANY WARRANTY; without even the implied warranty of
			MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
			GNU Affero General Public License for more details.
			You should have received a copy of the GNU Affero General Public License
			along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		DecTree class for reading in decision trees generated from scikit-learn.
 */

#ifndef DECTREE_H_INCLUDED
#define DECTREE_H_INCLUDED

#include <iostream>
#include <queue>
#include <limits.h>
#include <stdio.h>
#include <fstream>
#include <string>
#include <cstdlib>
#include <stdlib.h>
#include <time.h>
#include <vector>
#include <algorithm>
#include <stdint.h>
#include <random>
#include <math.h> /* pow */

using namespace std;

uint64_t largestPowerOfTwo(uint64_t N)
{
	// If N is 0, return 0
	if (N == 0)
	{
		return 0;
	}

	// Fill the higher bits with 1 through step-by-step bitwise operations
	N |= (N >> 1);
	N |= (N >> 2);
	N |= (N >> 4);
	N |= (N >> 8);
	N |= (N >> 16);
	N |= (N >> 32); // For a 64-bit integer, additionally process the upper 32 bits

	// N + 1 is the smallest power of two greater than N, and shifting it right by one bit yields the largest power of two less than or equal to N
	return (N + 1) >> 1;
}

void rotateRight(std::vector<int64_t> &vec, uint64_t k)
{
	// If the vector is empty or the number of rotations is 0, return immediately
	if (vec.empty() || k == 0)
	{
		return;
	}

	// Calculate the actual number of rotations to avoid k being larger than the size of the vector
	k = k % vec.size();

	// Reverse the entire vector
	std::reverse(vec.begin(), vec.end());

	// Reverse the first k elements
	std::reverse(vec.begin(), vec.begin() + k);

	// Reverse the remaining elements
	std::reverse(vec.begin() + k, vec.end());
}

bool isIndexInVector(const std::vector<uint32_t> &vec, uint32_t index)
{
	// Use std::find to search for an element
	auto it = std::find(vec.begin(), vec.end(), index);
	return it != vec.end(); // Return true if found, otherwise return false
}

bool contains(const std::vector<int64_t> &vec, int64_t value)
{
	// Use std::find to search for an element
	return std::find(vec.begin(), vec.end(), value) != vec.end();
}

class DecTree
{
public:
	struct Node
	{
		// Pointer to the first child node
		Node *left;
		// Pointer to the second child node
		Node *right;
		// Pointer to the first parent node
		Node *parent;
		// True if the edges coming into the node are already colored
		uint32_t level;
		// True if the node is a leaf
		bool leaf;
		// Threshold in decision node to compare with
		uint64_t threshold;
		// Threshold in decision node to compare with  leaf weight
		uint64_t classification;
		// Attribute index to compare with, -1 if undefined
		uint32_t attribute_index;
		// Node index
		uint32_t nodeIndex;
		// True node index
		bool TrueNode;
		// Whether the node has been swapped
		int32_t is_swap;

		Node();
		Node(const Node &);
	};

	// Vector of nodes that belong to the Gamma1 graph
	vector<Node *> node_vec;
	// Vector of decision nodes that belong to the Gamma1 graph
	vector<Node *> decnode_vec;
	// DummyTree
	Node *dummyTreeNode;
	// Extracted model attributes
	vector<int64_t> Extract_attributes;
	// Extracted model threshold
	vector<int64_t> Extract_thresholds;
	// Extracted model weights
	vector<int64_t> Extract_weights;
	// Node index status
	vector<int64_t> Extract_nodeIndex;
	// Node flipping status
	vector<int64_t> Extract_swapCondition;
	// Real node status
	vector<int64_t> Extract_trueNode;
	// Node** node_array;
	//  Vector of all attributes used for comparison with their occurrence
	vector<uint64_t> attributes;
	// Vector of all thresholds used for comparison with their occurrence
	vector<uint64_t> thresholds;

	// STATISTICS FOR DECISION TREES
	// number of attributes
	uint32_t num_attributes;
	// number of decision nodes
	uint32_t num_dec_nodes;
	// depth = largest level of leaves
	uint32_t depth;
	// number of leaves
	uint32_t num_of_leaves;
	// dummy in our case
	uint32_t dummy_non_full;

	DecTree();
	DecTree(const DecTree &);

	void add_node(Node *);
	void add_decnode(Node *);
	void add_edge(Node *, Node *);
	void read_from_file(string);
	void evaluate(vector<int64_t> inputs);
	void breadthFirstRead(uint64_t length);
	void ExtractModel(uint64_t length);
	void printTree(Node *node, int depth = 0);
	void OutputModel();
	void AddDummyNode(Node *dummyTree, vector<uint32_t> AllNodeIndex, int index);
	void PackHiddenMod(uint64_t length);
	void CopyNode(Node *dummyTree, Node *TrueTree);
	void RandomSwap(Node *dummyTree);
	void breadthFirstRead(Node *DummyTree);
	void depthfirstRead(Node *DummyTree, int index = 1);

	~DecTree();
};

void tokenize(const std::string &, std::vector<string> &);
void eraseSubStr(std::string &, const std::string &);

/**
 * Node constructor that takes its number num, by default it has no children
 * and parents, is not colored.
 * @param num the number that identifies the node
 */
DecTree::Node::Node()
	: left(0), right(0), parent(0), level(0), leaf(false), threshold(0), attribute_index(0), classification(0), nodeIndex(1), TrueNode(false), is_swap(1)
{
}

DecTree::Node::Node(const Node &other)
{
	left = new Node(*(other.left));
	right = new Node(*(other.right));
	parent = new Node(*(other.parent));
	level = other.level;
	leaf = other.leaf;
	threshold = other.threshold;
	attribute_index = other.attribute_index;
	classification = other.classification;
	nodeIndex = other.nodeIndex;
	TrueNode = other.TrueNode;
	is_swap = other.is_swap;
}

/**
 * Gamma2 constructor that creates a Gamma2 graph with specified number of Nodes
 * @param num the number specifying the number of Nodes
 */
DecTree::DecTree()
{
	num_attributes = 0;
	num_dec_nodes = 0;
	depth = 0;
	num_of_leaves = 0;
	dummy_non_full = 0;
}

DecTree::DecTree(const DecTree &other)
{
	node_vec = other.node_vec;
	decnode_vec = other.decnode_vec;
	attributes = other.attributes;
	thresholds = other.thresholds;
	num_attributes = other.num_attributes;
	num_dec_nodes = other.num_dec_nodes;
	depth = other.depth;
	num_of_leaves = other.num_of_leaves;
	dummy_non_full = other.dummy_non_full;
}

/**
 * Add a node
 * @param node the Node to be added to the tree
 */
void DecTree::add_node(DecTree::Node *node)
{
	node_vec.push_back(node);
}

/**
 * Add a decision node
 * @param node the Node to be added to the tree
 */
void DecTree::add_decnode(DecTree::Node *node)
{
	decnode_vec.push_back(node);
}

/**
 * Add an edge between two nodes
 * @param n1 the starting Node of the edge
 * @param n2 the ending Node of the edge
 */
void DecTree::add_edge(DecTree::Node *n1, DecTree::Node *n2)
{
	if (n2->parent == NULL)
	{
		n2->parent = n1;
		n2->level = n1->level + 1;
	}
	if (n1->left == NULL)
	{
		n1->left = n2;
		n2->nodeIndex = n1->nodeIndex * 2;
	}
	else if (n1->right == NULL)
	{
		n1->right = n2;
		n2->nodeIndex = n1->nodeIndex * 2 + 1;
	}
}

/**
 * Takes a string in the Format "i i i ..." separated by ' '
 * @param str the string to tokenize
 * @param tokens the result vector of wire id
 */
void tokenize(const std::string &str, std::vector<string> &tokens)
{
	tokens.clear();
	std::size_t prev = 0, pos;
	while ((pos = str.find_first_of(" [] \\ ", prev)) != std::string::npos)
	{
		if (pos > prev)
			tokens.push_back(str.substr(prev, pos - prev));
		prev = pos + 1;
	}
	if (prev < str.length())
		tokens.push_back(str.substr(prev, std::string::npos));
}

/**
 * Erase First Occurrence of given  substring from main string.
 */
void eraseSubStr(std::string &mainStr, const std::string &toErase)
{
	// Search for the substring in string
	size_t pos = mainStr.find(toErase);

	if (pos != std::string::npos)
	{
		// If found then erase it from string
		mainStr.erase(pos, toErase.length());
	}
}

class SearchFunction
{
public:
	SearchFunction(uint32_t item) : item_(item) {}
	bool operator()(std::uint64_t const &ref)
	{
		return ref == item_;
	}

private:
	uint32_t item_;
};

// root node will be in decnode_vec[0] and node_vec[0]
void DecTree::read_from_file(string string_file)
{
	const char *filename = string_file.c_str();
	ifstream file;
	file.open(filename);
	cout << filename << endl;

	// ofstream file2;
	// file2.open("dectree.txt", std::ios_base::app);

	uint32_t node1;
	uint32_t node2;

	DecTree::Node *node;
	uint32_t index;
	string line;
	vector<string> tokens;
	vector<uint64_t>::iterator it;
	float thres;
	while (getline(file, line))
	{
		tokenize(line, tokens);
		if (tokens[1] == "label=\"gini")
		{
			node1 = atoi(tokens[0].c_str());
			this->add_node(new DecTree::Node());
			this->node_vec[node1]->leaf = true;
			this->num_of_leaves++;
			this->node_vec[node1]->classification = atoi(tokens[6].c_str());
		}
		else if (tokens[1] == "label=\"X")
		{
			node1 = atoi(tokens[0].c_str());
			// cout << "node id" << node1 << " ";
			node = new DecTree::Node();
			index = atoi(tokens[2].c_str());
			node->attribute_index = index;
			// cout << "feature index" << index << " ";
			thres = atof(tokens[4].c_str());
			node->threshold = thres * 1000;
			// cout << "feature threshold" << node->threshold << endl; //Thresholds are converted so that we only compare integers
			this->num_dec_nodes++;
			this->add_node(node);
			this->add_decnode(node);

			it = find_if(this->attributes.begin(), this->attributes.end(), SearchFunction(index));
			if (it == this->attributes.end())
			{
				this->num_attributes++;
			}
			this->attributes.push_back(index);
			this->thresholds.push_back(node->threshold);
		}
		else if (tokens[1] == "->")
		{
			node1 = atoi(tokens[0].c_str());
			node2 = atoi(tokens[2].c_str());
			this->add_edge(this->node_vec[node1], this->node_vec[node2]);
		}
	}

	for (uint32_t i = 0; i < this->node_vec.size(); ++i)
	{
		node = this->node_vec[i];
		if (node->leaf)
		{ // Right is also 0 in this case
			if (node->level > this->depth)
			{
				this->depth = node->level;
			}
		}
	}

	for (uint32_t i = 0; i < this->node_vec.size(); ++i)
	{
		node = this->node_vec[i];
		if (node->leaf)
		{
			this->dummy_non_full += this->depth - node->level;
		}
	}

	uint32_t total_number_of_edges = 0;
	for (uint32_t i = 0; i < this->node_vec.size(); ++i)
	{
		node = this->node_vec[i];
		if (node->leaf)
		{
			total_number_of_edges += node->level;
		}
	}
	// cout << "Total number of edges " << total_number_of_edges << endl;
	file.close();
	// file2.close();
}

void DecTree::printTree(DecTree::Node *node, int depth)
{
	if (node == nullptr)
		return;

	// Print the indentation and attributes of the current node
	for (int i = 0; i < depth; ++i)
	{
		std::cout << "       "; // Use indentation to represent the depth of the node
	}

	if (node->leaf)
	{
		// Print the information of the leaf node
		std::cout << "Level = " << node->level << " Leaf Node: Classification = " << node->classification << std::endl;
	}
	else
	{
		// Print the information of the decision nodes
		std::cout << "Level = " << node->level << " Decision Node: Attribute Index = " << node->attribute_index
				  << ", Threshold = " << node->threshold << ", Whether it is a virtual node = " << node->TrueNode << std::endl;
	}

	// Recursively print the left and right child nodes
	printTree(node->left, depth + 1);
	printTree(node->right, depth + 1);
}

void DecTree::CopyNode(Node *dummyTree, Node *TrueTree)
{
	if (TrueTree == nullptr)
		return;

	if (TrueTree->left != nullptr)
	{
		DecTree::Node *node(TrueTree->left);
		dummyTree->left = node;
		node->parent = dummyTree;
		dummyTree->left->TrueNode = true;
	}

	if (TrueTree->right != nullptr)
	{
		DecTree::Node *node(TrueTree->right);
		dummyTree->right = node;
		node->parent = dummyTree;
		dummyTree->right->TrueNode = true;
	}

	CopyNode(dummyTree->left, TrueTree->left);
	CopyNode(dummyTree->right, TrueTree->right);
}

void DecTree::AddDummyNode(Node *dummyTree, vector<uint32_t> AllNodeIndex, int index)
{
	if (dummyTree->leaf)
		return;

	// If the current node is an empty node but a corresponding node exists in AllNodeIndex, add a virtual node
	if (dummyTree->left->leaf && isIndexInVector(AllNodeIndex, 2 * index))
	{
		// Construct a virtual decision node
		Node *NewDecnode = new Node();
		NewDecnode->level = dummyTree->left->level;
		NewDecnode->leaf = false;
		NewDecnode->threshold = rand() % 10000;
		NewDecnode->attribute_index = rand() % num_attributes;
		NewDecnode->nodeIndex = 2 * index;
		NewDecnode->TrueNode = false;

		// Construct the left node of the virtual decision node, directly inheriting
		Node *node(dummyTree->left);
		node->level = dummyTree->left->level + 1;

		// Construct the right node of the virtual decision node, with randomization
		Node *newLeaf = new Node();
		newLeaf->leaf = true;
		newLeaf->level = dummyTree->left->level + 1;
		newLeaf->classification = rand() % 500;

		dummyTree->left = NewDecnode;
		NewDecnode->parent = dummyTree;
		NewDecnode->left = node;
		node->parent = NewDecnode;
		NewDecnode->right = newLeaf;
		newLeaf->parent = NewDecnode;
	}

	if (dummyTree->right->leaf && isIndexInVector(AllNodeIndex, 2 * index + 1))
	{
		// Construct a virtual decision node
		Node *NewDecnode = new Node();
		NewDecnode->level = dummyTree->right->level;
		NewDecnode->leaf = false;
		NewDecnode->threshold = rand() % 10000;
		NewDecnode->attribute_index = rand() % num_attributes;
		NewDecnode->nodeIndex = 2 * index + 1;
		NewDecnode->TrueNode = false;

		// Construct the left node of the virtual decision node, directly inheriting
		Node *node(dummyTree->right);
		node->level = dummyTree->right->level + 1;

		// Construct the right node of the virtual decision node, with randomization
		Node *newLeaf = new Node();
		newLeaf->leaf = true;
		newLeaf->level = dummyTree->right->level + 1;
		newLeaf->classification = rand() % 500;

		dummyTree->right = NewDecnode;
		NewDecnode->parent = dummyTree;
		NewDecnode->left = node;
		node->parent = NewDecnode;
		NewDecnode->right = newLeaf;
		newLeaf->parent = NewDecnode;
	}

	AddDummyNode(dummyTree->left, AllNodeIndex, 2 * index);
	AddDummyNode(dummyTree->right, AllNodeIndex, 2 * index + 1);
}

void DecTree::RandomSwap(Node *dummyTree)
{
	if (dummyTree->leaf)
		return;

	// Create a random number generator using the default random engine
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_real_distribution<> dis(0.0, 1.0);

	// Generate a random number
	double randomValue = dis(gen);

	// Perform the swap with a random probability
	if (randomValue < 0.5)
		dummyTree->is_swap = -1;
	if (dummyTree->is_swap == -1)
	{
		Node *node = dummyTree->left;
		dummyTree->left = dummyTree->right;
		dummyTree->right = node;
	}

	RandomSwap(dummyTree->left);
	RandomSwap(dummyTree->right);
}

void DecTree::breadthFirstRead(Node *dummyTree)
{
	if (dummyTree == nullptr)
	{
		std::cout << "Tree is empty." << std::endl;
		return;
	}

	std::queue<Node *> q;
	q.push(dummyTree);

	// Breadth-first traversal
	int i = 0;
	while (!q.empty())
	{
		Node *currentNode = q.front();
		q.pop();

		Extract_attributes.push_back(currentNode->attribute_index);
		Extract_thresholds.push_back(currentNode->threshold);
		Extract_swapCondition.push_back(currentNode->is_swap);
		Extract_trueNode.push_back(currentNode->TrueNode ? 1 : 0);

		// std::cout << "i: " << i << "Node index: " << currentNode->nodeIndex << std::endl;
		// i++;

		// If there is a left child node, add it to the queue
		if (!currentNode->left->leaf)
		{
			q.push(currentNode->left);
		}

		// If there is a right child node, add it to the queue
		if (!currentNode->right->leaf)
		{
			q.push(currentNode->right);
		}
	}
}

void DecTree::depthfirstRead(Node *dummyTree, int index)
{
	if (dummyTree->leaf)
	{
		Extract_weights.push_back(dummyTree->classification);
		return;
	}
	Extract_nodeIndex.push_back(index);

	depthfirstRead(dummyTree->left, index * 2);
	depthfirstRead(dummyTree->right, index * 2 + 1);
}

// Add Dummy Node
void DecTree::PackHiddenMod(uint64_t length)
{
	if (this->node_vec[0] == nullptr)
	{
		std::cout << "Tree is empty." << std::endl;
		return;
	}
	cout << "Total number of nodes " << length << " ";
	int dummyNumber = length - this->num_dec_nodes;
	cout << "Number of virtual nodes " << dummyNumber << " ";

	vector<uint32_t> TrueNodeIndex;
	vector<uint32_t> AllNodeIndex;

	for (uint32_t i = 0; i < this->node_vec.size(); ++i)
	{
		Node *node = this->node_vec[i];
		if (!node->leaf)
		{
			TrueNodeIndex.push_back(node->nodeIndex);
		}
	}

	AllNodeIndex = TrueNodeIndex;

	for (size_t i = 0; i < length; i++)
	{
		if (!isIndexInVector(AllNodeIndex, AllNodeIndex[i] * 2))
		{
			if (dummyNumber > 0)
			{
				AllNodeIndex.push_back(AllNodeIndex[i] * 2);
				dummyNumber--;
			}
		}

		if (!isIndexInVector(AllNodeIndex, AllNodeIndex[i] * 2 + 1))
		{
			if (dummyNumber > 0)
			{
				AllNodeIndex.push_back(AllNodeIndex[i] * 2 + 1);
				dummyNumber--;
			}
		}
	}

	cout << endl;

	Node *DummyTree(node_vec[0]);
	DummyTree->TrueNode = true;

	// Copy the real node
	CopyNode(DummyTree, node_vec[0]);

	// Add a virtual node
	AddDummyNode(DummyTree, AllNodeIndex, 1);
	// printTree(DummyTree);

	cout << "\n\n"
		 << endl;

	// Random permutation
	RandomSwap(DummyTree);
	// printTree(DummyTree);

	depthfirstRead(DummyTree);
	breadthFirstRead(DummyTree);

	// OutputModel();
}

void DecTree::OutputModel()
{
	cout << "Feature index: ";
	print_vector(Extract_attributes, 24, 0);

	cout << "\nModel threshold: ";
	print_vector(Extract_thresholds, 24, 0);

	cout << "\nModel weights: ";
	print_vector(Extract_weights, 24, 0);

	cout << "\nNode index status: ";
	std::sort(Extract_nodeIndex.begin(), Extract_nodeIndex.end());
	print_vector(Extract_nodeIndex, 24, 0);

	cout << "\nNode swap status: ";
	print_vector(Extract_swapCondition, 24, 0);

	cout << "\nReal node status: ";
	print_vector(Extract_trueNode, 24, 0);
}

// Evaluate the original model
void DecTree::evaluate(vector<int64_t> inputs)
{
	DecTree::Node *this_node = this->node_vec[0];
	// printTree(this->node_vec[0], 0);
	cout << "Output the prediction path";
	int i = 1;
	while (!(this_node->leaf))
	{
		cout << i - 1 << " ";
		if ((inputs[this_node->attribute_index]))
		{
			this_node = this_node->left;
			i = 2 * i;
		}
		else
		{
			this_node = this_node->right;
			i = 2 * i + 1;
		}
	}
	cout << "True prediction results: " << " ";
	cout << this_node->classification << endl;
}

/**
 * Destructor DecTree
 */
DecTree::~DecTree()
{
	node_vec.clear();
}

#endif // DECTREE_H_INCLUDED
