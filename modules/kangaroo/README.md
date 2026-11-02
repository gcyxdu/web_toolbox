# Kangaroo: A Private and Amortized Inference Framework over WAN for Large-Scale Decision Tree Evaluation

Kangaroo is a high-performance framework designed for secure decision tree inference in two key scenarios:

1. **Two-Party Secure Inference:** Enables privacy-preserving decision tree inference between two parties.
2. **Single-Cloud Outsourced Model Inference:** Supports secure and efficient decision tree inference for outsourced models in a single-cloud environment.

* Kangaroo can also be combined with other algorithms to support different application scenarios, such as performing feature selection via our feature selection algorithm, secure comparison through polynomial approximation, and path evaluation using Path cost-based evaluation algorithm, while leveraging GPUs to further accelerate non-interactive decision tree inference. This approach highlights Kangaroo’s design of treating each polynomial coefficient as a node, fully exploiting the advantages of SIMD and GPU parallelism for inference. Moreover, in certain high-dimensional feature selection tasks, replacing our feature selection algorithm with an OT-based protocol may further improve efficiency. 

### Table of Contents.

- [Requirements](#requirements)
- [Kangaroo Source Code]()
    - [Repository Structure](#repository-structure)
    - [Building Kangaroo](#building-kangaroo)
    - [Microsoft SEAL Installation](#microsoft-SEAL-installation)
    - [Running Kangaroo](#running-kangaroo)
    - [Real-World Application Showcase](#real-World-application-showcase)
    - [Dataset](#dataset)
    - [Plaintext Model](#plaintext-model)
    - [License](#license)

### Requirements
---
* The code should work on any Linux distribution of your choice (It has been developed and tested with [Ubuntu](http://www.ubuntu.com/) 22.04).

* **Required packages for Kangaroo**
	* [`g++`](https://packages.debian.org/testing/g++)
	* [`make`](https://packages.debian.org/testing/make)
	* [`seal`](https://github.com/microsoft/SEAL)

We use g++(11.4.0), make(4.3), seal(4.1). 

### Kangaroo Source Code
---

#### Repository Structure

* `Kangaroo for client-server model-correct` - Verify the correctness of the scheme.
* `Kangaroo for client-server model-time` - Measure the time overhead of a two-way security reasoning scheme.
* `Kangaroo for client-server model-communication`    - Measurement communication overhead of a two-way security reasoning scheme.
* `Kangaroo for outsourcing model-time`    - Measure the time overhead of a Single-Cloud Outsourced security reasoning scheme.
* `Kangaroo for outsourcing model-communication` - Measurement communication overhead of a Single-Cloud Outsourced.
* `Kangaroo for WAN` - Deploying Kangaroo in Real-World Applications.

#### Building Kangaroo

To build Kangaroo, you just need to download our code as follows：

```sh
git clone (the web URL of our repository)
```

####  Microsoft SEAL Installation

`git clone https://github.com/microsoft/SEAL.git`

`cd SEAL`

`cmake -S . -B build`

`cmake --build build`

`sudo cmake --install build`

#### Running Kangaroo

Simply navigate to the folder you want to test and run `./1.sh`.

To deploy Kangaroo in real-world scenarios, the Kangaroo-for-WAN codebase should be set up on two separate platforms. Make sure to configure the IP addresses appropriately and avoid firewall restrictions.

* Configuring IP Addresses and Ports

1. Ensure that the server-side deployment opens the correct port. In our setup, we use port 5000 (see line 803 in server.cpp and line 768 in client.cpp).

2. Make sure the port numbers in client.cpp (line 768) and server.cpp (line 803) are consistent with the server’s port setting.

3. Set the IP address in client.cpp (line 769) to the server’s IP address.

Then, navigate to the Kangaroo-for-WAN directory and execute `./1.sh` to launch the deployment. Next, run `./server` on one platform and `./client` on the other platform.

#### Real-World Application Showcase

We deployed our servers across different cloud platforms to simulate realistic WAN conditions. One of the servers was hosted on JD Cloud, equipped with a single CPU thread, 3.8 GB RAM, and an Intel(R) Xeon(R) Gold 6148 CPU @ 2.40 GHz, running Ubuntu 22.04.5. Another server was deployed on Alibaba Cloud, equipped with a single CPU thread, 4 GB RAM, and an Intel(R) Xeon(R) Platinum CPU @ 2.50 GHz, also running Ubuntu 22.04.5. Our client was deployed on a ThinkPad-P53 machine with single thread, 23.1 GB RAM, and an Intel Core i5-9400H 2.50GHz processor running on Ubuntu 18.04.6. The reported runtime results are measured from the moment the feature vector is sent until the computation result is received. The time for key initialization and model initialization is not included in the statistics, since, as mentioned in our paper (Same-Sharing-for-Same-Model), these steps are performed once and can be reused.

![image](https://github.com/pigeon-xw/Kangaroo/tree/main/IMG/1750643231053.jpg)

#### Dataset

We place our datasets under the UCI_dectrees directory and provide a test.py script to visualize the structure of each decision tree model.

#### Plaintext Model

We provide plaintext model evaluation code in BFSdectree.hpp, where the DecTree::evaluate interface can be used to evaluate the corresponding decision tree model. The plaintext running time (ms) is shown as follows:

![image](https://github.com/pigeon-xw/Kangaroo/blob/main/IMG/PlaintextRunningTime.jpg)

#### License

This code is released for **academic research and testing purposes only**. Commercial use is prohibited. If you use this code in your research, please cite our paper: [Kangaroo: A Private and Amortized Inference Framework over WAN for Large-Scale Decision Tree Evaluation].
