#include <common/attestation_t.h>
#include <common/dispatcher.h>
#include <openenclave/enclave.h>

// Secret data for this enclave
uint8_t g_enclave_secret_data[ENCLAVE_SECRET_DATA_SIZE] =
    {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

// For single-enclave setup, we don't need another enclave's public key
// Set it to null and size to 0
enclave_config_data_t config_data = {
    g_enclave_secret_data,
    nullptr,  // No other enclave in single-enclave setup
    0        // No other enclave public key size
};

// Create dispatcher for this single enclave
static ecall_dispatcher dispatcher("SingleEnclave", &config_data);
const char* enclave_name = "SingleEnclave";

// EDL function implementations
int get_enclave_format_settings(
    const oe_uuid_t* format_id,
    format_settings_t* format_settings)
{
    return dispatcher.get_enclave_format_settings(format_id, format_settings);
}

int get_evidence_with_public_key(
    const oe_uuid_t* format_id,
    format_settings_t* format_settings,
    pem_key_t* pem_key,
    evidence_t* evidence)
{
    return dispatcher.get_evidence_with_public_key(
        format_id, format_settings, pem_key, evidence);
}

// NEW: Set host's public key for result encryption
int set_host_public_key(pem_key_t* host_public_key)
{
    return dispatcher.set_host_public_key(host_public_key);
}

// UPDATED: DeFi processing function now returns encrypted results + attestation
int process_encrypted_defi(message_t* encrypted_defi_package, message_t* response)
{
    return dispatcher.process_encrypted_defi(encrypted_defi_package, response);
}