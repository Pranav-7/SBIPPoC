// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "dispatcher.h"
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/report.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/enclave.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <cstring>

ecall_dispatcher::ecall_dispatcher(
    const char* name,
    enclave_config_data_t* enclave_config)
    : m_crypto(nullptr), m_attestation(nullptr), m_host_key_set(false), m_host_public_key_size(0)
{
    m_enclave_config = enclave_config;
    m_initialized = initialize(name);
    
    // Initialize host public key storage
    memset(m_host_public_key, 0, sizeof(m_host_public_key));
}

ecall_dispatcher::~ecall_dispatcher()
{
    if (m_crypto)
        delete m_crypto;

    if (m_attestation)
        delete m_attestation;
}

bool ecall_dispatcher::initialize(const char* name)
{
    bool ret = false;

    m_name = name;
    m_crypto = new Crypto();
    if (m_crypto == nullptr)
    {
        goto exit;
    }

    // Handle single-enclave mode (when other_enclave_public_key_pem is nullptr)
    if (m_enclave_config->other_enclave_public_key_pem != nullptr && 
        m_enclave_config->other_enclave_public_key_pem_size > 0)
    {
        // Dual-enclave mode: get signer ID from other enclave's public key
        size_t other_enclave_signer_id_size = sizeof(m_other_enclave_signer_id);
        if (oe_sgx_get_signer_id_from_public_key(
                m_enclave_config->other_enclave_public_key_pem,
                m_enclave_config->other_enclave_public_key_pem_size,
                m_other_enclave_signer_id,
                &other_enclave_signer_id_size) != OE_OK)
        {
            TRACE_ENCLAVE("Failed to get signer ID from other enclave's public key");
            goto exit;
        }
    }
    else
    {
        // Single-enclave mode: set dummy signer ID (won't be used for verification)
        TRACE_ENCLAVE("Single-enclave mode: no other enclave signer ID needed");
        memset(m_other_enclave_signer_id, 0, sizeof(m_other_enclave_signer_id));
    }

    m_attestation = new Attestation(m_crypto, m_other_enclave_signer_id);
    if (m_attestation == nullptr)
    {
        goto exit;
    }
    ret = true;

exit:
    return ret;
}

int ecall_dispatcher::get_enclave_format_settings(
    const oe_uuid_t* format_id,
    format_settings_t* format_settings)
{
    uint8_t* format_settings_buffer = nullptr;
    size_t format_settings_size = 0;
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

    // Generate a format settings so that the enclave that receives this format
    // settings can attest this enclave.
    TRACE_ENCLAVE("get_enclave_format_settings");
    if (m_attestation->get_format_settings(
            format_id, &format_settings_buffer, &format_settings_size) == false)
    {
        TRACE_ENCLAVE("get_enclave_format_settings failed");
        goto exit;
    }

    if (format_settings_buffer && format_settings_size)
    {
        format_settings->buffer = (uint8_t*)malloc(format_settings_size);
        if (format_settings->buffer == nullptr)
        {
            ret = OE_OUT_OF_MEMORY;
            TRACE_ENCLAVE("copying format_settings failed, out of memory");
            goto exit;
        }
        memcpy(
            format_settings->buffer,
            format_settings_buffer,
            format_settings_size);
        format_settings->size = format_settings_size;
        oe_verifier_free_format_settings(format_settings_buffer);
    }
    else
    {
        format_settings->buffer = nullptr;
        format_settings->size = 0;
    }
    ret = 0;

exit:

    if (ret != 0)
        TRACE_ENCLAVE("get_enclave_format_settings failed.");
    return ret;
}

/**
 * Return the public key of this enclave along with the enclave's
 * evidence. The enclave that receives the key will use the evidence to
 * attest this enclave.
 */
int ecall_dispatcher::get_evidence_with_public_key(
    const oe_uuid_t* format_id,
    format_settings_t* format_settings,
    pem_key_t* pem_key,
    evidence_t* evidence)
{
    uint8_t pem_public_key[512];
    uint8_t* evidence_buffer = nullptr;
    size_t evidence_size = 0;
    int ret = 1;

    TRACE_ENCLAVE("get_evidence_with_public_key");
    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    m_crypto->retrieve_public_key(pem_public_key);

    // Generate evidence for the public key so that the enclave that
    // receives the key can attest this enclave.
    if (m_attestation->generate_attestation_evidence(
            format_id,
            format_settings->buffer,
            format_settings->size,
            pem_public_key,
            sizeof(pem_public_key),
            &evidence_buffer,
            &evidence_size) == false)
    {
        TRACE_ENCLAVE("get_evidence_with_public_key failed");
        goto exit;
    }

    evidence->buffer = (uint8_t*)malloc(evidence_size);
    if (evidence->buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying evidence_buffer failed, out of memory");
        goto exit;
    }
    memcpy(evidence->buffer, evidence_buffer, evidence_size);
    evidence->size = evidence_size;
    oe_free_evidence(evidence_buffer);

    pem_key->buffer = (uint8_t*)malloc(sizeof(pem_public_key));
    if (pem_key->buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying key_buffer failed, out of memory");
        goto exit;
    }
    memcpy(pem_key->buffer, pem_public_key, sizeof(pem_public_key));
    pem_key->size = sizeof(pem_public_key);

    ret = 0;
    TRACE_ENCLAVE("get_evidence_with_public_key succeeded");

exit:
    if (ret != 0)
    {
        if (evidence_buffer)
            oe_free_evidence(evidence_buffer);
        if (pem_key)
        {
            free(pem_key->buffer);
            pem_key->size = 0;
        }
        if (evidence)
        {
            free(evidence->buffer);
            evidence->size = 0;
        }
    }
    return ret;
}

int ecall_dispatcher::verify_evidence_and_set_public_key(
    const oe_uuid_t* format_id,
    pem_key_t* pem_key,
    evidence_t* evidence)
{
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    // Attest the evidence and accompanying key.
    if (m_attestation->attest_attestation_evidence(
            format_id,
            evidence->buffer,
            evidence->size,
            pem_key->buffer,
            pem_key->size) == false)
    {
        TRACE_ENCLAVE("verify_evidence_and_set_public_key failed.");
        goto exit;
    }

    memcpy(
        m_crypto->get_the_other_enclave_public_key(),
        pem_key->buffer,
        pem_key->size);

    ret = 0;
    TRACE_ENCLAVE("verify_evidence_and_set_public_key succeeded.");

exit:
    return ret;
}

// ============================================================================
// NEW: HOST PUBLIC KEY MANAGEMENT
// ============================================================================

int ecall_dispatcher::set_host_public_key(pem_key_t* host_public_key)
{
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    if (host_public_key == nullptr || host_public_key->buffer == nullptr || host_public_key->size == 0)
    {
        TRACE_ENCLAVE("Invalid host public key provided");
        goto exit;
    }

    if (host_public_key->size > sizeof(m_host_public_key))
    {
        TRACE_ENCLAVE("Host public key too large: %zu bytes (max: %zu)", 
                      host_public_key->size, sizeof(m_host_public_key));
        goto exit;
    }

    // Store the host's public key and its actual size
    memcpy(m_host_public_key, host_public_key->buffer, host_public_key->size);
    m_host_public_key_size = host_public_key->size;
    m_host_key_set = true;
    
    TRACE_ENCLAVE("✅ Host public key stored successfully (%zu bytes)", host_public_key->size);
    ret = 0;

exit:
    return ret;
}

// ============================================================================
// HELPER FUNCTIONS FOR ENCRYPTED RESPONSE
// ============================================================================

bool ecall_dispatcher::encrypt_result_for_host(const char* plaintext_result, size_t result_size, 
                                               uint8_t** encrypted_result, size_t* encrypted_size)
{
    BIO* mem = nullptr;
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* rsa_ctx = nullptr;
    EVP_CIPHER_CTX* aes_ctx = nullptr;
    bool success = false;
    uint8_t* temp_encrypted = nullptr;
    uint8_t aes_key[32]; // 256-bit AES key
    uint8_t aes_iv[16];  // 128-bit IV
    uint8_t* encrypted_aes_key = nullptr;
    size_t encrypted_aes_key_size = 0;
    uint8_t* aes_encrypted_data = nullptr;
    int aes_encrypted_len = 0;
    int final_len = 0;
    
    // Declare variables that were causing goto issues
    uint32_t key_size = 0;
    size_t total_size = 0;

    if (!m_host_key_set)
    {
        TRACE_ENCLAVE("❌ Host public key not set - cannot encrypt result");
        return false;
    }

    TRACE_ENCLAVE("🔐 Using hybrid encryption (AES+RSA) for large result (%zu bytes)", result_size);

    // Generate random AES key and IV
    if (!RAND_bytes(aes_key, sizeof(aes_key)) || !RAND_bytes(aes_iv, sizeof(aes_iv)))
    {
        TRACE_ENCLAVE("❌ Failed to generate AES key/IV");
        goto cleanup;
    }

    // Step 1: Encrypt data with AES-256-CBC
    aes_ctx = EVP_CIPHER_CTX_new();
    if (!aes_ctx)
    {
        TRACE_ENCLAVE("❌ Failed to create AES context");
        goto cleanup;
    }

    if (!EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv))
    {
        TRACE_ENCLAVE("❌ Failed to initialize AES encryption");
        goto cleanup;
    }

    // Allocate buffer for AES encrypted data (plaintext + block size for padding)
    aes_encrypted_data = (uint8_t*)malloc(result_size + 16);
    if (!aes_encrypted_data)
    {
        TRACE_ENCLAVE("❌ Failed to allocate AES buffer");
        goto cleanup;
    }

    if (!EVP_EncryptUpdate(aes_ctx, aes_encrypted_data, &aes_encrypted_len, (const uint8_t*)plaintext_result, result_size))
    {
        TRACE_ENCLAVE("❌ AES encryption update failed");
        goto cleanup;
    }

    if (!EVP_EncryptFinal_ex(aes_ctx, aes_encrypted_data + aes_encrypted_len, &final_len))
    {
        TRACE_ENCLAVE("❌ AES encryption final failed");
        goto cleanup;
    }

    aes_encrypted_len += final_len;
    TRACE_ENCLAVE("✅ AES encryption successful (%zu -> %d bytes)", result_size, aes_encrypted_len);

    // Step 2: Encrypt AES key with RSA
    // Create BIO from PEM public key
    mem = BIO_new(BIO_s_mem());
    if (!mem || !BIO_write(mem, m_host_public_key, m_host_public_key_size))
    {
        TRACE_ENCLAVE("❌ Failed to create BIO for host public key");
        goto cleanup;
    }

    // Parse PEM public key
    pkey = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
    if (!pkey)
    {
        TRACE_ENCLAVE("❌ Failed to parse host public key");
        goto cleanup;
    }

    // Create RSA encryption context
    rsa_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!rsa_ctx || !EVP_PKEY_encrypt_init(rsa_ctx))
    {
        TRACE_ENCLAVE("❌ Failed to initialize RSA encryption context");
        goto cleanup;
    }

    // Set padding
    if (!EVP_PKEY_CTX_set_rsa_padding(rsa_ctx, RSA_PKCS1_OAEP_PADDING))
    {
        TRACE_ENCLAVE("❌ Failed to set RSA padding");
        goto cleanup;
    }

    // Get encrypted AES key size
    if (!EVP_PKEY_encrypt(rsa_ctx, NULL, &encrypted_aes_key_size, aes_key, sizeof(aes_key)))
    {
        TRACE_ENCLAVE("❌ Failed to get RSA encrypted size");
        goto cleanup;
    }

    // Allocate buffer for encrypted AES key
    encrypted_aes_key = (uint8_t*)malloc(encrypted_aes_key_size);
    if (!encrypted_aes_key)
    {
        TRACE_ENCLAVE("❌ Failed to allocate RSA buffer");
        goto cleanup;
    }

    // Encrypt AES key with RSA
    if (!EVP_PKEY_encrypt(rsa_ctx, encrypted_aes_key, &encrypted_aes_key_size, aes_key, sizeof(aes_key)))
    {
        TRACE_ENCLAVE("❌ Failed to encrypt AES key with RSA");
        goto cleanup;
    }

    TRACE_ENCLAVE("✅ RSA encryption of AES key successful (%zu bytes)", encrypted_aes_key_size);

    // Step 3: Create final hybrid encrypted package
    // Format: [4 bytes: encrypted_aes_key_size][encrypted_aes_key][16 bytes: IV][aes_encrypted_data]
    total_size = 4 + encrypted_aes_key_size + 16 + aes_encrypted_len;
    temp_encrypted = (uint8_t*)malloc(total_size);
    if (!temp_encrypted)
    {
        TRACE_ENCLAVE("❌ Failed to allocate final buffer");
        goto cleanup;
    }

    // Pack the hybrid encrypted data
    key_size = (uint32_t)encrypted_aes_key_size;
    memcpy(temp_encrypted, &key_size, 4);                           // AES key size
    memcpy(temp_encrypted + 4, encrypted_aes_key, encrypted_aes_key_size); // Encrypted AES key
    memcpy(temp_encrypted + 4 + encrypted_aes_key_size, aes_iv, 16); // IV
    memcpy(temp_encrypted + 4 + encrypted_aes_key_size + 16, aes_encrypted_data, aes_encrypted_len); // AES encrypted data

    *encrypted_result = temp_encrypted;
    *encrypted_size = total_size;
    temp_encrypted = nullptr; // Don't free on cleanup
    success = true;
    TRACE_ENCLAVE("✅ Hybrid encryption successful (%zu -> %zu bytes)", result_size, total_size);

cleanup:
    if (mem) BIO_free(mem);
    if (pkey) EVP_PKEY_free(pkey);
    if (rsa_ctx) EVP_PKEY_CTX_free(rsa_ctx);
    if (aes_ctx) EVP_CIPHER_CTX_free(aes_ctx);
    if (encrypted_aes_key) free(encrypted_aes_key);
    if (aes_encrypted_data) free(aes_encrypted_data);
    if (temp_encrypted) free(temp_encrypted);
    
    // Clear sensitive data
    memset(aes_key, 0, sizeof(aes_key));
    
    return success;
}

bool ecall_dispatcher::generate_attestation_for_result(const char* result_data, 
                                                      uint8_t** attestation_evidence, size_t* attestation_size)
{
    // Use the proper SGX ECDSA format UUID for remote attestation
    oe_uuid_t sgx_ecdsa_uuid = OE_FORMAT_UUID_SGX_ECDSA;
    
    TRACE_ENCLAVE("🛡️ Generating SGX ECDSA attestation for result...");
    
    // Initialize the attester
    oe_result_t result = oe_attester_initialize();
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("❌ oe_attester_initialize failed: %s", oe_result_str(result));
        return false;
    }

    // Generate hash of the result data to include in attestation
    uint8_t result_hash[32];
    if (!m_crypto->Sha256((const uint8_t*)result_data, strlen(result_data), result_hash))
    {
        TRACE_ENCLAVE("❌ Failed to hash result data");
        oe_attester_shutdown();
        return false;
    }

    // Generate SGX ECDSA evidence with the result hash as custom claims
    result = oe_get_evidence(
        &sgx_ecdsa_uuid,                    // format_id: SGX ECDSA
        0,                                  // flags: no special flags
        result_hash,                        // custom_claims_buffer: hash of result
        sizeof(result_hash),                // custom_claims_buffer_size
        nullptr,                            // opt_params: none needed
        0,                                  // opt_params_size
        attestation_evidence,               // evidence_buffer (output)
        attestation_size,                   // evidence_buffer_size (output)  
        nullptr,                            // endorsements_buffer (not needed)
        nullptr);                           // endorsements_buffer_size (not needed)

    if (result != OE_OK)
    {
        TRACE_ENCLAVE("❌ oe_get_evidence failed: %s", oe_result_str(result));
        oe_attester_shutdown();
        return false;
    }

    TRACE_ENCLAVE("✅ SGX ECDSA attestation generated successfully (%zu bytes)", *attestation_size);
    
    // Shutdown attester
    oe_attester_shutdown();
    
    return true;
}

void ecall_dispatcher::bytes_to_hex_string(const uint8_t* bytes, size_t byte_count, char* hex_string)
{
    const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < byte_count; i++)
    {
        hex_string[i * 2] = hex_chars[(bytes[i] >> 4) & 0x0F];
        hex_string[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    hex_string[byte_count * 2] = '\0';
}

// ============================================================================
// DEFI HELPER FUNCTIONS - Add these to dispatcher.cpp
// ============================================================================

const char* ecall_dispatcher::get_token_name(int32_t token_type)
{
    switch (token_type) {
        case TOKEN_ETH: return "ETH";
        case TOKEN_USDC: return "USDC";
        case TOKEN_BTC: return "BTC";
        case TOKEN_USDT: return "USDT";
        default: return "UNKNOWN";
    }
}

const char* ecall_dispatcher::get_solver_name(int32_t solver_type)
{
    switch (solver_type) {
        case SOLVER_BASIC_SWAP: return "basic_swap";
        case SOLVER_MEV_ARBITRAGE: return "mev_arbitrage";
        case SOLVER_PRIVATE_LIQUIDITY: return "private_liquidity";
        default: return "unknown_solver";
    }
}

ExecutionResult ecall_dispatcher::execute_basic_swap(
    const CompactTradingIntent& intent,
    const CompactPublicState& public_state,
    const CompactSolver& solver)
{
    ExecutionResult result = {0};
    
    TRACE_ENCLAVE("Executing basic swap: %.2f %s -> %s", 
                  intent.amount, 
                  get_token_name(intent.from_token),
                  get_token_name(intent.to_token));

    // Simple price calculation
    double base_output = intent.amount * public_state.eth_price;
    double final_output = base_output - solver.execution_fee;
    
    result.output_amount = final_output;
    result.mev_captured = 0.0;
    result.gas_cost = public_state.gas_price * 0.021; // Standard transfer gas
    result.constraints_satisfied = (final_output >= intent.min_receive);
    result.status_code = result.constraints_satisfied ? 0 : 1;
    
    snprintf(result.solver_used, sizeof(result.solver_used), "%s", get_solver_name(solver.algorithm_type));
    snprintf(result.status_message, sizeof(result.status_message), 
             result.constraints_satisfied ? "Basic swap successful" : "Insufficient output");
             
    TRACE_ENCLAVE("Basic swap result: %.2f USDC, constraints %s", 
                  result.output_amount, 
                  result.constraints_satisfied ? "satisfied" : "not satisfied");
                  
    return result;
}

ExecutionResult ecall_dispatcher::execute_mev_arbitrage(
    const CompactTradingIntent& intent,
    const CompactPrivateState& private_state,
    const CompactPublicState& public_state,
    const CompactSolver& solver)
{
    ExecutionResult result = {0};
    
    TRACE_ENCLAVE("Executing MEV arbitrage: %.2f %s -> %s", 
                  intent.amount,
                  get_token_name(intent.from_token),
                  get_token_name(intent.to_token));

    // Base swap calculation
    double base_output = intent.amount * public_state.eth_price;
    
    // MEV capture logic
    double mev_capture = private_state.mev_opportunity * 0.8; // Capture 80% of MEV
    double gas_cost = public_state.gas_price * 0.15; // Higher gas for MEV bot
    
    // Final calculation
    double final_output = base_output + mev_capture - solver.execution_fee - gas_cost;
    
    result.output_amount = final_output;
    result.mev_captured = mev_capture;
    result.gas_cost = gas_cost;
    result.constraints_satisfied = (final_output >= intent.min_receive);
    result.status_code = result.constraints_satisfied ? 0 : 1;
    
    snprintf(result.solver_used, sizeof(result.solver_used), "%s", get_solver_name(solver.algorithm_type));
    snprintf(result.status_message, sizeof(result.status_message),
             result.constraints_satisfied ? "MEV arbitrage successful" : "MEV execution failed");
             
    TRACE_ENCLAVE("MEV arbitrage result: %.2f USDC, MEV captured: %.2f", 
                  result.output_amount, result.mev_captured);
                  
    return result;
}

ExecutionResult ecall_dispatcher::execute_private_liquidity(
    const CompactTradingIntent& intent,
    const CompactPrivateState& private_state,
    const CompactPublicState& public_state,
    const CompactSolver& solver)
{
    ExecutionResult result = {0};
    
    TRACE_ENCLAVE("Executing private liquidity access: %.2f %s -> %s", 
                  intent.amount,
                  get_token_name(intent.from_token),
                  get_token_name(intent.to_token));

    // Base swap calculation
    double base_output = intent.amount * public_state.eth_price;
    
    // Private liquidity bonus
    double liquidity_bonus = 0.0;
    if (private_state.secret_liquidity >= intent.amount) {
        // Can use private liquidity - get better rates
        liquidity_bonus = private_state.private_pool_balance * 0.005; // 0.5% of private pool
        TRACE_ENCLAVE("Private liquidity available: +%.2f USDC bonus", liquidity_bonus);
    } else {
        TRACE_ENCLAVE("Insufficient private liquidity");
    }
    
    double gas_cost = public_state.gas_price * 0.025; // Slightly higher gas
    double final_output = base_output + liquidity_bonus - solver.execution_fee - gas_cost;
    
    result.output_amount = final_output;
    result.mev_captured = liquidity_bonus; // Store bonus as "MEV captured"
    result.gas_cost = gas_cost;
    result.constraints_satisfied = (final_output >= intent.min_receive);
    result.status_code = result.constraints_satisfied ? 0 : 1;
    
    snprintf(result.solver_used, sizeof(result.solver_used), "%s", get_solver_name(solver.algorithm_type));
    snprintf(result.status_message, sizeof(result.status_message),
             result.constraints_satisfied ? "Private liquidity successful" : "Private liquidity failed");
             
    TRACE_ENCLAVE("Private liquidity result: %.2f USDC, bonus: %.2f", 
                  result.output_amount, liquidity_bonus);
                  
    return result;
}

// ============================================================================
// UPDATED MAIN DEFI PROCESSING FUNCTION - NOW WITH ENCRYPTED RESPONSE + ATTESTATION
// ============================================================================

// FIXED FUNCTION: Move large buffers from stack to heap to prevent stack overflow
int ecall_dispatcher::process_encrypted_defi(message_t* encrypted_defi_package, message_t* response)
{
    int ret = 1;
    
    // FIXED: Use heap allocation instead of stack for large buffers
    uint8_t* decrypted_data = nullptr;
    char* plaintext_result = nullptr;
    char* final_json_response = nullptr;
    
    size_t decrypted_size = 512; // Size for CompactDefiPackage
    size_t response_size = 0;
    uint8_t* response_buffer = nullptr;
    uint8_t* encrypted_result = nullptr;
    size_t encrypted_result_size = 0;
    uint8_t* attestation_evidence = nullptr;
    size_t attestation_size = 0;
    ExecutionResult result = {0};
    CompactDefiPackage* defi_package = nullptr;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

    // FIXED: Allocate large buffers on heap
    decrypted_data = (uint8_t*)malloc(512);
    plaintext_result = (char*)malloc(2048);
    final_json_response = (char*)malloc(16384);
    
    if (!decrypted_data || !plaintext_result || !final_json_response)
    {
        TRACE_ENCLAVE("❌ Failed to allocate buffers");
        ret = OE_OUT_OF_MEMORY;
        goto exit;
    }

    if (!m_host_key_set)
    {
        TRACE_ENCLAVE("❌ Host public key not set - cannot provide encrypted response");
        response_size = snprintf(final_json_response, 16384,
                "{\n"
                "  \"error\": \"Host public key not set\",\n"
                "  \"encrypted_result\": null,\n"
                "  \"attestation\": null\n"
                "}");
        goto create_response;
    }

    TRACE_ENCLAVE("🔐 process_encrypted_defi: received %zu bytes of encrypted DeFi data", 
                  encrypted_defi_package->size);

    // Decrypt the DeFi package using enclave's private key
    if (!m_crypto->Decrypt(
            encrypted_defi_package->data,
            encrypted_defi_package->size,
            decrypted_data,
            &decrypted_size))
    {
        TRACE_ENCLAVE("Failed to decrypt DeFi package");
        response_size = snprintf(final_json_response, 16384,
                "{\n"
                "  \"error\": \"Failed to decrypt DeFi package\",\n"
                "  \"encrypted_result\": null,\n"
                "  \"attestation\": null\n"
                "}");
        goto create_response;
    }

    TRACE_ENCLAVE("Successfully decrypted %zu bytes", decrypted_size);

    // Validate decrypted data size
    if (decrypted_size != sizeof(CompactDefiPackage))
    {
        TRACE_ENCLAVE("Invalid DeFi package size: %zu bytes (expected %zu)", 
                      decrypted_size, sizeof(CompactDefiPackage));
        
        response_size = snprintf(final_json_response, 16384,
                "{\n"
                "  \"error\": \"Invalid DeFi package format\",\n"
                "  \"encrypted_result\": null,\n"
                "  \"attestation\": null\n"
                "}");
        goto create_response;
    }

    defi_package = (CompactDefiPackage*)decrypted_data;
    
    TRACE_ENCLAVE("=== DeFi Package Parsed ===");
    TRACE_ENCLAVE("Intent: %.2f %s -> %s (min: %.2f)", 
                  defi_package->intent.amount,
                  get_token_name(defi_package->intent.from_token),
                  get_token_name(defi_package->intent.to_token),
                  defi_package->intent.min_receive);
    TRACE_ENCLAVE("Solver: %s (fee: %.2f)", 
                  get_solver_name(defi_package->solver.algorithm_type),
                  defi_package->solver.execution_fee);

    // Execute based on solver algorithm
    switch (defi_package->solver.algorithm_type)
    {
        case SOLVER_BASIC_SWAP:
            result = execute_basic_swap(
                defi_package->intent,
                defi_package->public_st,
                defi_package->solver);
            break;
            
        case SOLVER_MEV_ARBITRAGE:
            result = execute_mev_arbitrage(
                defi_package->intent,
                defi_package->private_st,
                defi_package->public_st,
                defi_package->solver);
            break;
            
        case SOLVER_PRIVATE_LIQUIDITY:
            result = execute_private_liquidity(
                defi_package->intent,
                defi_package->private_st,
                defi_package->public_st,
                defi_package->solver);
            break;
            
        default:
            TRACE_ENCLAVE("Unknown solver type: %d", defi_package->solver.algorithm_type);
            response_size = snprintf(final_json_response, 16384,
                    "{\n"
                    "  \"error\": \"Unknown solver algorithm type: %d\",\n"
                    "  \"encrypted_result\": null,\n"
                    "  \"attestation\": null\n"
                    "}", defi_package->solver.algorithm_type);
            goto create_response;
    }

    // Create plaintext result
    snprintf(plaintext_result, 2048,
        "=== ENCLAVE DEFI EXECUTION RESULT ===\n"
        "Intent UID: %s\n"
        "Trade: %.4f %s -> %.4f %s\n"
        "Solver: %s\n"
        "Status: %s (Code: %d)\n"
        "Output Amount: %.4f USDC\n"
        "Minimum Required: %.4f USDC\n"
        "Constraints: %s\n"
        "MEV/Bonus Captured: %.4f USDC\n"
        "Gas Cost: %.4f USDC\n"
        "Net Profit: %.4f USDC\n"
        "Execution: Verified inside SGX enclave\n"
        "Block: %d, ETH Price: $%.2f\n"
        "=== END RESULT ===\n",
        defi_package->intent.intent_uid,
        defi_package->intent.amount,
        get_token_name(defi_package->intent.from_token),
        result.output_amount,
        get_token_name(defi_package->intent.to_token),
        result.solver_used,
        result.status_message,
        result.status_code,
        result.output_amount,
        defi_package->intent.min_receive,
        result.constraints_satisfied ? "SATISFIED" : "NOT SATISFIED",
        result.mev_captured,
        result.gas_cost,
        result.output_amount - defi_package->intent.min_receive,
        defi_package->public_st.block_number,
        defi_package->public_st.eth_price);

    // 🔐 ENCRYPT THE RESULT FOR HOST
    TRACE_ENCLAVE("🔐 Encrypting result for host...");
    if (!encrypt_result_for_host(plaintext_result, strlen(plaintext_result), &encrypted_result, &encrypted_result_size))
    {
        TRACE_ENCLAVE("❌ Failed to encrypt result for host");
        response_size = snprintf(final_json_response, 16384,
                "{\n"
                "  \"error\": \"Failed to encrypt result\",\n"
                "  \"encrypted_result\": null,\n"
                "  \"attestation\": null\n"
                "}");
        goto create_response;
    }
    
    TRACE_ENCLAVE("✅ Result encrypted successfully (%zu bytes)", encrypted_result_size);

    // 🛡️ GENERATE ATTESTATION FOR THE RESULT
    TRACE_ENCLAVE("🛡️ Generating attestation for result...");
    if (!generate_attestation_for_result(plaintext_result, &attestation_evidence, &attestation_size))
    {
        TRACE_ENCLAVE("❌ Failed to generate attestation");
        response_size = snprintf(final_json_response, 16384,
                "{\n"
                "  \"error\": \"Failed to generate attestation\",\n"
                "  \"encrypted_result\": null,\n"
                "  \"attestation\": null\n"
                "}");
        goto create_response;
    }
    
    TRACE_ENCLAVE("✅ Attestation generated successfully (%zu bytes)", attestation_size);

    // 📦 CREATE FINAL JSON RESPONSE WITH ENCRYPTED RESULT + ATTESTATION
    {
        // Convert encrypted result to hex string
        char* encrypted_hex = (char*)malloc(encrypted_result_size * 2 + 1);
        if (!encrypted_hex)
        {
            response_size = snprintf(final_json_response, 16384,
                    "{\n"
                    "  \"error\": \"Memory allocation failed for hex conversion\",\n"
                    "  \"encrypted_result\": null,\n"
                    "  \"attestation\": null\n"
                    "}");
            goto create_response;
        }
        bytes_to_hex_string(encrypted_result, encrypted_result_size, encrypted_hex);

        // Convert attestation to hex string
        char* attestation_hex = (char*)malloc(attestation_size * 2 + 1);
        if (!attestation_hex)
        {
            free(encrypted_hex);
            response_size = snprintf(final_json_response, 16384,
                    "{\n"
                    "  \"error\": \"Memory allocation failed for attestation hex\",\n"
                    "  \"encrypted_result\": null,\n"
                    "  \"attestation\": null\n"
                    "}");
            goto create_response;
        }
        bytes_to_hex_string(attestation_evidence, attestation_size, attestation_hex);

        // Create the final JSON response
        response_size = snprintf(final_json_response, 16384,
            "{\n"
            "  \"encrypted_result\": \"%s\",\n"
            "  \"attestation\": \"%s\",\n"
            "  \"metadata\": {\n"
            "    \"intent_uid\": \"%s\",\n"
            "    \"solver_used\": \"%s\",\n"
            "    \"status_code\": %d,\n"
            "    \"encrypted_size\": %zu,\n"
            "    \"attestation_size\": %zu,\n"
            "    \"execution_time\": \"SGX_ENCLAVE\"\n"
            "  }\n"
            "}",
            encrypted_hex,
            attestation_hex,
            defi_package->intent.intent_uid,
            result.solver_used,
            result.status_code,
            encrypted_result_size,
            attestation_size);

        free(encrypted_hex);
        free(attestation_hex);
    }

create_response:
    // Allocate buffer for response
    response_buffer = (uint8_t*)malloc(response_size + 1);
    if (response_buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("Failed to allocate response buffer");
        goto exit;
    }

    // Copy response to buffer
    memcpy(response_buffer, final_json_response, response_size);
    response_buffer[response_size] = '\0';

    // Set up response structure
    response->data = response_buffer;
    response->size = response_size;

    TRACE_ENCLAVE("🎉 Encrypted DeFi response created (size: %zu bytes)", response_size);
    ret = 0;

exit:
    // FIXED: Cleanup heap-allocated buffers
    if (decrypted_data) free(decrypted_data);
    if (plaintext_result) free(plaintext_result);
    if (final_json_response) free(final_json_response);
    if (encrypted_result) free(encrypted_result);
    if (attestation_evidence) oe_free_evidence(attestation_evidence);
    
    if (ret != 0 && response_buffer != nullptr)
    {
        free(response_buffer);
        response->data = nullptr;
        response->size = 0;
    }
    return ret;
}