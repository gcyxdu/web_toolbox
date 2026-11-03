#ifndef SECURE_BERT_H
#define SECURE_BERT_H

#include <array>
#include <chrono>
#include <vector>
#include <iostream>
#include <cstring>
#include "epo_snn_64.h"

struct BertConfig {
    int batch_size = 1;
    int seq_len = 128;
    int hidden_size = 768;
    int num_heads = 12;
    int head_dim = 64;
    int intermediate_size = 3072;
    uint64_t scale = 20;
    int party_id = 0;
    std::vector<int> attention_mask;
};

struct SecureTensor {
    std::vector<uint64_t> shares;
    int rows;
    int cols;

    SecureTensor() : rows(0), cols(0) {}
    SecureTensor(int r, int c) : rows(r), cols(c) {
        shares.resize(r * c, 0);
    }

    void resize(int r, int c) {
        rows = r;
        cols = c;
        shares.assign(static_cast<size_t>(r) * static_cast<size_t>(c), 0);
    }

    uint64_t* data() { return shares.data(); }
    const uint64_t* data() const { return shares.data(); }
    size_t size() const { return shares.size(); }

    SecureTensor operator+(const SecureTensor& other) const {
        SecureTensor res(rows, cols);
        for(size_t i = 0; i < shares.size(); i++) {
            res.shares[i] = shares[i] + other.shares[i];
        }
        return res;
    }
};

enum class BertCommCategory : size_t {
    Embedding = 0,
    Conv,
    MatMul,
    Softmax,
    GeLU,
    LayerNorm,
    Count
};

struct BertCommCategoryStats {
    unsigned long long send_calls = 0;
    unsigned long long recv_calls = 0;
    unsigned long long send_bytes = 0;
    unsigned long long recv_bytes = 0;
    unsigned long long round_correction = 0;
    long long elapsed_us = 0;
};

extern std::array<BertCommCategoryStats, static_cast<size_t>(BertCommCategory::Count)> g_bert_comm_stats;
extern std::vector<BertCommCategory> g_bert_comm_category_overrides;

static inline const char* bert_comm_category_name(BertCommCategory category) {
    switch (category) {
        case BertCommCategory::Embedding: return "embedding";
        case BertCommCategory::Conv: return "conv";
        case BertCommCategory::MatMul: return "matmul";
        case BertCommCategory::Softmax: return "softmax";
        case BertCommCategory::GeLU: return "gelu";
        case BertCommCategory::LayerNorm: return "layernorm";
        case BertCommCategory::Count: break;
    }
    return "unknown";
}

static inline void reset_bert_comm_profile() {
    g_bert_comm_stats = {};
    g_bert_comm_category_overrides.clear();
}

static inline const std::array<BertCommCategoryStats, static_cast<size_t>(BertCommCategory::Count)>&
get_bert_comm_profile() {
    return g_bert_comm_stats;
}

static inline BertCommCategory resolve_bert_comm_category(BertCommCategory category) {
    if (!g_bert_comm_category_overrides.empty()) {
        return g_bert_comm_category_overrides.back();
    }
    return category;
}

class ScopedBertCommCategoryOverride {
public:
    explicit ScopedBertCommCategoryOverride(BertCommCategory category) {
        g_bert_comm_category_overrides.push_back(category);
    }

    ~ScopedBertCommCategoryOverride() {
        if (!g_bert_comm_category_overrides.empty()) {
            g_bert_comm_category_overrides.pop_back();
        }
    }
};

class ScopedBertCommProfile {
public:
    explicit ScopedBertCommProfile(BertCommCategory category, unsigned long long round_correction = 0)
        : category_(resolve_bert_comm_category(category)),
          before_(get_bsnet_stats()),
          round_correction_(round_correction) {}

    ~ScopedBertCommProfile() {
        const auto after_tp = std::chrono::high_resolution_clock::now();
        const BSNetStatsSnapshot after = get_bsnet_stats();
        BertCommCategoryStats& stats = g_bert_comm_stats[static_cast<size_t>(category_)];
        stats.send_calls += (after.send_calls - before_.send_calls);
        stats.recv_calls += (after.recv_calls - before_.recv_calls);
        stats.send_bytes += (after.send_bytes - before_.send_bytes);
        stats.recv_bytes += (after.recv_bytes - before_.recv_bytes);
        stats.round_correction += round_correction_;
        stats.elapsed_us += std::chrono::duration_cast<std::chrono::microseconds>(after_tp - start_tp_).count();
    }

private:
    BertCommCategory category_;
    BSNetStatsSnapshot before_;
    unsigned long long round_correction_;
    std::chrono::high_resolution_clock::time_point start_tp_ = std::chrono::high_resolution_clock::now();
};

void Op_GeLU(SecureTensor& io, const CommPorts& ports);
void Op_Softmax(SecureTensor& io, const CommPorts& ports);
void Op_LayerNorm(SecureTensor& io, const SecureTensor& gamma, const SecureTensor& beta, const CommPorts& ports);
void Op_LayerNorm(SecureTensor& io, const SecureTensor& gamma, const SecureTensor& beta,
                  const CommPorts& ports, int inv_steep_k1, int inv_flat_k1, int inv_k2);

#endif
