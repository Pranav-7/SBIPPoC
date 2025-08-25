// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma once
#include <openenclave/enclave.h>
#include <string>
#include "attestation.h"
#include "crypto.h"

using namespace std;

typedef struct _enclave_config_data
{
    uint8_t* enclave_secret_data;
    const char* other_enclave_public_key_pem;
    size_t other_enclave_public_key_pem_size;
} enclave_config_data_t;

// ============================================================================
// DeFi STRUCTURES - Designed to fit within RSA encryption limits (<190 bytes)
// ============================================================================

enum TokenType {
    TOKEN_ETH = 0,
    TOKEN_USDC = 1,
    TOKEN_BTC = 2,
    TOKEN_USDT = 3
};

enum SolverType {
    SOLVER_BASIC_SWAP = 0,
    SOLVER_MEV_ARBITRAGE = 1, 
    SOLVER_PRIVATE_LIQUIDITY = 2
};

// Compact trading intent - 44 bytes
struct CompactTradingIntent {
    double amount;              // 8 bytes - Amount to trade
    double min_receive;         // 8 bytes - Minimum acceptable output
    int32_t from_token;         // 4 bytes - TokenType enum
    int32_t to_token;           // 4 bytes - TokenType enum  
    char intent_uid[20];        // 20 bytes - Unique identifier
    // Total: 44 bytes
};

// Compact private state - 32 bytes
struct CompactPrivateState {
    double secret_liquidity;    // 8 bytes - Solver's private liquidity
    double mev_opportunity;     // 8 bytes - MEV opportunity value
    double private_pool_balance;// 8 bytes - Access to private pools
    int32_t exchange_access;    // 4 bytes - Private exchange ID
    int32_t reserved;           // 4 bytes - For alignment/future use
    // Total: 32 bytes
};

// Compact public state - 24 bytes
struct CompactPublicState {
    double eth_price;           // 8 bytes - Current ETH price
    double gas_price;           // 8 bytes - Current gas price
    int32_t block_number;       // 4 bytes - Current block
    int32_t reserved;           // 4 bytes - For alignment
    // Total: 24 bytes
};

// Compact solver configuration - 16 bytes  
struct CompactSolver {
    int32_t algorithm_type;     // 4 bytes - SolverType enum
    double execution_fee;       // 8 bytes - Fee for execution
    int32_t reserved;           // 4 bytes - For future use
    // Total: 16 bytes
};

// Complete DeFi package - 116 bytes (well within RSA limits!)
struct CompactDefiPackage {
    CompactTradingIntent intent;    // 44 bytes
    CompactPrivateState private_st; // 32 bytes  
    CompactPublicState public_st;   // 24 bytes
    CompactSolver solver;           // 16 bytes
    // Total: 116 bytes - Safe for RSA-2048 encryption!
};

// Execution result structure for response
struct ExecutionResult {
    double output_amount;           // Final output amount
    double mev_captured;            // MEV value captured
    double gas_cost;                // Gas costs incurred
    bool constraints_satisfied;     // Did we meet min_receive?
    int32_t status_code;            // Success/failure code
    char solver_used[32];           // Which solver was used
    char status_message[64];        // Human-readable status
};

// ============================================================================
// EXISTING DISPATCHER CLASS WITH DEFI EXTENSIONS
// ============================================================================

class ecall_dispatcher
{
  private:
    bool m_initialized;
    Crypto* m_crypto;
    Attestation* m_attestation;
    string m_name;
    enclave_config_data_t* m_enclave_config;
    unsigned char m_other_enclave_signer_id[32];

    // NEW: Storage for host's public key
    uint8_t m_host_public_key[512];
    size_t m_host_public_key_size;
    bool m_host_key_set;

    // DeFi execution helpers
    ExecutionResult execute_basic_swap(
        const CompactTradingIntent& intent,
        const CompactPublicState& public_state,
        const CompactSolver& solver);
        
    ExecutionResult execute_mev_arbitrage(
        const CompactTradingIntent& intent,
        const CompactPrivateState& private_state,
        const CompactPublicState& public_state,
        const CompactSolver& solver);
        
    ExecutionResult execute_private_liquidity(
        const CompactTradingIntent& intent,
        const CompactPrivateState& private_state,
        const CompactPublicState& public_state,
        const CompactSolver& solver);

    const char* get_token_name(int32_t token_type);
    const char* get_solver_name(int32_t solver_type);

    // NEW: Helper functions for encrypted response
    bool encrypt_result_for_host(const char* plaintext_result, size_t result_size, 
                                uint8_t** encrypted_result, size_t* encrypted_size);
    bool generate_attestation_for_result(const char* result_data, 
                                       uint8_t** attestation_evidence, size_t* attestation_size);
    void bytes_to_hex_string(const uint8_t* bytes, size_t byte_count, char* hex_string);

  public:
    ecall_dispatcher(const char* name, enclave_config_data_t* enclave_config);
    ~ecall_dispatcher();
    
    // Original functions (unchanged)
    int get_enclave_format_settings(
        const oe_uuid_t* format_id,
        format_settings_t* format_settings);

    int get_evidence_with_public_key(
        const oe_uuid_t* format_id,
        format_settings_t* format_settings,
        pem_key_t* pem_key,
        evidence_t* evidence);

    int verify_evidence_and_set_public_key(
        const oe_uuid_t* format_id,
        pem_key_t* pem_key,
        evidence_t* evidence);
    
    // NEW: Set host's public key for result encryption
    int set_host_public_key(pem_key_t* host_public_key);
    
    // UPDATED: DeFi processing function now returns encrypted results + attestation
    int process_encrypted_defi(message_t* encrypted_defi_package, message_t* response);

  private:
    bool initialize(const char* name);
};