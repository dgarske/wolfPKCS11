# TPM Memory Consumption Test

This test creates 10 RSA private keys and 10 X.509 certificates using `C_CreateObject` to evaluate TPM memory consumption in wolfPKCS11.

## Purpose

The test is designed to:
- Generate multiple RSA key pairs and certificates
- Insert them into the TPM using PKCS#11 `C_CreateObject` calls
- Monitor TPM memory usage and detect potential memory exhaustion
- Provide a reproducible test case for TPM memory consumption analysis
- Automatically handle token initialization when running on a fresh token

## Files

- `tests/tpm_memory_test.c` - Main test implementation
- `tpm_memory_test_data.h` - Generated RSA keys and certificate data
- `extract_key_data.py` - Python script to generate test data from OpenSSL keys
- `test_keys/` - Directory containing generated PEM files
- `TPM_MEMORY_TEST.md` - This documentation

## Building

The test is integrated into the wolfPKCS11 build system:

```bash
make tests/tpm_memory_test
```

## Running the Test

### Basic Usage

```bash
./tests/tpm_memory_test
```

### Command Line Options

```bash
./tests/tpm_memory_test [options]

Options:
  -?                 Help, print usage information
  -lib <file>        PKCS#11 library to test (default: ./src/.libs/libwolfpkcs11.so)
  -slot <num>        Slot number to use (default: 1)
  -userPin <string>  User PIN (default: wolfpkcs11-test)
  -v                 Verbose output
```

### Example with Verbose Output

```bash
./tests/tpm_memory_test -v
```

## Test Data Generation

The test uses pre-generated RSA keys and certificates. To regenerate the test data:

1. Generate new keys and certificates:
```bash
mkdir -p test_keys
cd test_keys
for i in {1..10}; do 
    openssl genrsa -out rsa_key_${i}.pem 2048
    openssl req -new -x509 -key rsa_key_${i}.pem -out cert_${i}.pem -days 365 \
        -subj "/C=US/ST=TestState/L=TestCity/O=TestOrg/OU=TestUnit/CN=test${i}.example.com"
done
cd ..
```

2. Extract key components and certificate data:
```bash
python3 extract_key_data.py
```

This generates `tpm_memory_test_data.h` with C arrays containing the RSA key components and certificate DER data.

## Test Details

### RSA Keys Created

The test creates 10 RSA-2048 private keys, each containing:
- Modulus (n)
- Public exponent (e) - standard 65537
- Private exponent (d)
- Prime 1 (p)
- Prime 2 (q)
- Exponent 1 (dP = d mod (p-1))
- Exponent 2 (dQ = d mod (q-1))
- Coefficient (qInv = q^-1 mod p)

### Certificates Created

The test creates 10 X.509 certificates in DER format, each corresponding to one of the RSA keys.

### PKCS#11 Attributes

#### RSA Private Key Attributes
- `CKA_CLASS`: `CKO_PRIVATE_KEY`
- `CKA_KEY_TYPE`: `CKK_RSA`
- `CKA_DECRYPT`: `CK_TRUE`
- `CKA_SIGN`: `CK_TRUE`
- `CKA_TOKEN`: `CK_TRUE` (persistent storage)
- `CKA_PRIVATE`: `CK_TRUE`
- RSA-specific attributes (modulus, exponents, primes, etc.)

#### Certificate Attributes
- `CKA_CLASS`: `CKO_CERTIFICATE`
- `CKA_CERTIFICATE_TYPE`: `CKC_X_509`
- `CKA_TOKEN`: `CK_TRUE` (persistent storage)
- `CKA_VALUE`: DER-encoded certificate data

## Expected Behavior

### Success Case
- Automatically initializes token if needed (first run or fresh token)
- All 20 objects (10 keys + 10 certificates) are created successfully
- Test reports "SUCCESS: All objects created successfully"
- Objects are automatically cleaned up after the test

### Failure Cases
- TPM memory exhaustion: Test will fail when TPM runs out of memory
- Invalid key data: Malformed RSA components will cause creation to fail
- Authentication issues: Invalid PIN or session problems
- Token initialization failure: Issues with SO PIN or token setup

## Monitoring TPM Memory

This test is specifically designed to stress-test TPM memory consumption. Monitor your TPM's memory usage during the test using TPM-specific tools or logs.

### Potential Indicators of Memory Issues
- `C_CreateObject` returns `CKR_DEVICE_MEMORY` or similar error codes
- Test fails partway through object creation
- Subsequent TPM operations fail due to memory exhaustion

## Cleanup

The test automatically cleans up all created objects using `C_DestroyObject`. However, if the test is interrupted, objects may remain in the token storage and consume TPM memory.

To manually clean up:
1. Use a PKCS#11 tool to enumerate and delete objects
2. Reset the token storage (implementation-dependent)
3. Restart the TPM (hardware-dependent)

## Integration with CI/CD

This test can be integrated into continuous integration workflows to:
- Detect TPM memory regressions
- Validate memory management improvements
- Ensure consistent behavior across different TPM implementations

## Troubleshooting

### Common Issues

1. **Compilation errors**: Ensure wolfPKCS11 is properly configured and built
2. **Library not found**: Check the `-lib` parameter points to the correct PKCS#11 library
3. **Authentication failures**: Test automatically handles token initialization for fresh tokens
4. **TPM not available**: Ensure TPM is enabled and accessible
5. **Token initialization**: The test uses SO PIN "wolfpkcs11-so-test" and user PIN "wolfpkcs11-test"

### Debug Output

Use the `-v` flag for verbose output showing each operation's success/failure status.

## Performance Considerations

- Each RSA-2048 key consumes significant TPM memory (typically 1-4KB depending on implementation)
- Certificate storage requirements vary based on certificate size
- Total memory consumption: approximately 20-80KB for the complete test

## Modifications

To test different scenarios:

1. **More objects**: Increase the loop counters in `create_rsa_keys_and_certs()`
2. **Larger keys**: Generate RSA-4096 keys instead of RSA-2048
3. **Different algorithms**: Add ECC keys and certificates
4. **Stress testing**: Run the test repeatedly without cleanup

## Security Notes

- Test keys are for testing purposes only - do not use in production
- Private keys are embedded in the test binary - not suitable for sensitive operations
- Test certificates are self-signed and not validated by any CA
- Default PINs are used for testing - change for production environments
- Token initialization uses predictable SO PIN "wolfpkcs11-so-test"