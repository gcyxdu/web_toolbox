#include "SecureBert.h"
#include "base_secure_protocols.h"
#include "epo_snn_64.h"





static uint64_t local_secure_truncate(uint64_t value, int shift_bits) {
    if (value < (1ULL << 63)) {
        
        return value >> shift_bits;
    } else {
        
        uint64_t complement = UINT64_MAX - value + 1;
        uint64_t truncated = complement >> shift_bits;
        return UINT64_MAX - truncated + 1;
    }
}

static uint64_t multiply_public_fixed_share_local(uint64_t share, uint64_t public_coeff, int shift_bits) {
    __int128 share_signed = static_cast<__int128>(static_cast<int64_t>(share));
    __int128 coeff_signed = static_cast<__int128>(static_cast<int64_t>(public_coeff));
    __int128 product = share_signed * coeff_signed;
    __int128 shifted = product >> shift_bits;
    return static_cast<uint64_t>(static_cast<int64_t>(shifted));
}


static void truncate_tensor_inplace(SecureTensor& tensor, int shift_bits) {
    for(size_t i = 0; i < tensor.shares.size(); i++) {
        tensor.shares[i] = local_secure_truncate(tensor.shares[i], shift_bits);
    }
}


void Op_MatMul(const SecureTensor& A, const SecureTensor& B, SecureTensor& C, const CommPorts& ports) {
    
    if (A.cols != B.rows) {
        printf("Error: MatMul shape mismatch (%dx%d) * (%dx%d)\n", A.rows, A.cols, B.rows, B.cols);
        return;
    }

    
    secure_matrix_batch_dualport_csp1(
        ports.main_server, ports.main_client,  
        A.data(), B.data(), C.data(),
        1,                  
        A.rows, A.cols, B.cols
    );

    truncate_tensor_inplace(C, 20);
}




void Op_GeLU(SecureTensor& io, const CommPorts& ports) {
    private_approx_gelu_2rounds_csp1(
        ports,
        io.data(), io.data(), 
        io.size(),
        1, 6, UINT64_MAX 
    );
}




void Op_Softmax(SecureTensor& io, const CommPorts& ports) {
    private_approx_softmax_csp1(
        ports,
        io.data(), io.data(),
        io.rows, io.cols,
        3, 12,   
        3, 1, 12, 12,   
        UINT64_MAX
    );
}




void Op_Add(const SecureTensor& A, const SecureTensor& B, SecureTensor& out) {
    for(size_t i=0; i<A.shares.size(); i++) {
        out.shares[i] = A.shares[i] + B.shares[i];
    }
}




void Op_AddBias(SecureTensor& mat, const SecureTensor& bias, const CommPorts& ports) {
    if (mat.cols != bias.cols) {
        printf("Error: Bias dim mismatch\n");
        return;
    }
    
    for (int r = 0; r < mat.rows; r++) {
        for (int c = 0; c < mat.cols; c++) {
            mat.shares[r * mat.cols + c] += bias.shares[c]; 
        }
    }
}






void Op_LayerNorm(SecureTensor& io, const SecureTensor& gamma, const SecureTensor& beta,
                  const CommPorts& ports, int inv_steep_k1, int inv_flat_k1, int inv_k2) {
    int rows = io.rows;
    int cols = io.cols;
    int N = rows * cols;
    const uint64_t s = 20;

    uint64_t inv_N = (uint64_t)std::round((1.0 / cols) * (1ULL << s));

    
    std::vector<uint64_t> mean_vec(rows);
    for(int r = 0; r < rows; r++) {
        uint64_t sum = 0;
        for(int c = 0; c < cols; c++) sum += io.shares[r * cols + c];
        mean_vec[r] = multiply_public_fixed_share_local(sum, inv_N, s);
    }

    
    std::vector<uint64_t> x_sq(N);
    secure_multiply_batch_dualport(
        ports.main_client, ports.main_server, false,
        io.shares.data(), io.shares.data(), x_sq.data(),
        N, s, UINT64_MAX
    );
    
    for(int i = 0; i < N; i++) x_sq[i] = local_secure_truncate(x_sq[i], s);

    
    std::vector<uint64_t> ex2_vec(rows);
    for(int r = 0; r < rows; r++) {
        uint64_t sum = 0;
        for(int c = 0; c < cols; c++) sum += x_sq[r * cols + c];
        ex2_vec[r] = multiply_public_fixed_share_local(sum, inv_N, s);
    }

    
    std::vector<uint64_t> mean_sq(rows);
    secure_multiply_batch_dualport(
        ports.main_client, ports.main_server, false,
        mean_vec.data(), mean_vec.data(), mean_sq.data(),
        rows, s, UINT64_MAX
    );
    
    for(int i = 0; i < rows; i++) mean_sq[i] = local_secure_truncate(mean_sq[i], s);

    
    
    const uint64_t eps_fp = 1;
    std::vector<uint64_t> var_vec(rows);
    for(int r = 0; r < rows; r++) {
        var_vec[r] = ex2_vec[r] - mean_sq[r] + eps_fp;
    }

    
    std::vector<uint64_t> inv_std_vec(rows);
    private_approx_invsqrt_plus_csp1(
        ports, var_vec.data(), inv_std_vec.data(),
        rows, inv_steep_k1, inv_flat_k1, inv_k2, UINT64_MAX
    );

    std::vector<uint64_t> centered(N);
    for(int r = 0; r < rows; r++)
        for(int c = 0; c < cols; c++)
            centered[r*cols+c] = io.shares[r*cols+c] - mean_vec[r];

    
    std::vector<uint64_t> inv_std_broadcast(N);
    for(int r = 0; r < rows; r++)
        for(int c = 0; c < cols; c++)
            inv_std_broadcast[r*cols+c] = inv_std_vec[r];

    
    std::vector<uint64_t> norm(N);
    secure_multiply_batch_dualport(
        ports.main_client, ports.main_server, false,
        centered.data(), inv_std_broadcast.data(), norm.data(),
        N, s, UINT64_MAX
    );
    
    for(int i = 0; i < N; i++) norm[i] = local_secure_truncate(norm[i], s);

    
    std::vector<uint64_t> gamma_broadcast(N);
    for(int r = 0; r < rows; r++)
        for(int c = 0; c < cols; c++)
            gamma_broadcast[r*cols+c] = gamma.shares[c];

    std::vector<uint64_t> scaled(N);
    secure_multiply_batch_dualport(
        ports.main_client, ports.main_server, false,
        norm.data(), gamma_broadcast.data(), scaled.data(),
        N, s, UINT64_MAX
    );
    for(int i = 0; i < N; i++) scaled[i] = local_secure_truncate(scaled[i], s);

    
    for(int r = 0; r < rows; r++)
        for(int c = 0; c < cols; c++)
            io.shares[r*cols+c] = scaled[r*cols+c] + beta.shares[c];

}

void Op_LayerNorm(SecureTensor& io, const SecureTensor& gamma, const SecureTensor& beta, const CommPorts& ports) {
    Op_LayerNorm(io, gamma, beta, ports, 3, 1, 12);
}
