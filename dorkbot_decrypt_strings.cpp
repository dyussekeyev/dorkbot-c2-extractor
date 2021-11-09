#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <fstream>
#include <sstream>
#include <string>

int hex2int(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    return -1;
}

int main()
{
    char Key[44] = { 0x08, 0x02, 0x00, 0x00, 0x10, 0x66, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
                     0x47, 0x44, 0x21, 0x62, 0x72, 0x57, 0x4A, 0x4A, 0x42, 0x65, 0x54, 0x67, 0x54, 0x47, 0x53, 0x67,
                     0x45, 0x46, 0x42, 0x2F, 0x71, 0x75, 0x52, 0x63, 0x66, 0x43, 0x6B, 0x42, 0x48, 0x57, 0x67, 0x6C };
    char C2[32] = { 0 };
    int hbyte, lbyte;
 
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    DWORD dwMode;
    DWORD dwCount;

    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        printf("Error during CryptAcquireContext! Error number = %x\n", GetLastError());
        exit(1);
    }

    if (!CryptImportKey(hCryptProv, (const BYTE *) Key, 0x2C, 0, 0, &hKey))
    {
        printf("Error during CryptImportKey! Error number = %x\n", GetLastError());
        exit(1);
    }

    dwMode = 2;
    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*) &dwMode, 0)) {
        printf("Error during CryptSetKeyParam! Error number = %x\n", GetLastError());
        exit(1);
    }

    std::ifstream infile("strings_list.txt");
    std::string line;
    while (std::getline(infile, line))
    {
        std::istringstream iss(line);
        const char* cstr = line.c_str();

        for (int i = 0; i < strlen(cstr) / 2; i++) {
            hbyte = hex2int(*(cstr + 2*i));
            lbyte = hex2int(*(cstr + 2*i + 1));
            C2[i] = (hbyte << 4) ^ lbyte;
        }

        dwCount = strlen(cstr) / 2;
        if (!CryptDecrypt(hKey, 0, 1, 0, (BYTE*)C2, &dwCount))
        {
            printf("Error during CryptDecrypt! Error number = %x\n", GetLastError());
            exit(1);
        }

        printf("%s\n", C2);
    }

    if (!CryptReleaseContext(hCryptProv, 0))
    {
        printf("Error during CryptReleaseContext! Error number = %x\n", GetLastError());
        exit(1);
    }

    return 0;
}
