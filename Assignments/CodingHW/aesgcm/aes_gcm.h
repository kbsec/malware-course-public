#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define AES_256_KEY_SIZE    (256/8)
#define AES_BLOCK_SIZE        16

class AESGCM{

    BOOL status = FALSE;
    NTSTATUS nStatus;

    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
   
    void Cleanup();
   
    public:

        void Decrypt(BYTE* nonce, size_t nonceLen, BYTE* data, size_t dataLen, BYTE* macTag, size_t macTagLen);
        void Encrypt(BYTE *nonce, size_t nonceLen, BYTE *data, size_t dataLen);
         AESGCM(BYTE key[AES_256_KEY_SIZE]); // initialize with key 
         ~AESGCM();
        BYTE* tag = NULL; // pointer to message authentication code
        BYTE* ciphertext = NULL; // pointer to ciphertext
        BCRYPT_AUTH_TAG_LENGTHS_STRUCT authTagLengths;
        DWORD ptBufferSize = 0; // pointer to plaintext size
        BYTE* plaintext = NULL; // pointer to plaintext


};