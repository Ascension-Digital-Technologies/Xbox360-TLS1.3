#include "xboxtls/platform.h"
#if defined(_WIN32) && !defined(_XBOX)
#define WIN32_LEAN_AND_MEAN
#include <wincrypt.h>
#include <windows.h>
namespace xboxtls {
class Win32Platform : public Platform {
  public:
    virtual Error random_bytes(MutableByteSpan out) {
        HCRYPTPROV p = 0;
        if (!CryptAcquireContext(&p, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
            return XT_ERR_CRYPTO;
        BOOL ok = CryptGenRandom(p, (DWORD)out.size, out.data);
        CryptReleaseContext(p, 0);
        return ok ? XT_OK : XT_ERR_CRYPTO;
    }
    virtual xt_u64 unix_time_seconds() {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER u;
        u.LowPart = ft.dwLowDateTime;
        u.HighPart = ft.dwHighDateTime;
        return (xt_u64)((u.QuadPart - 116444736000000000ULL) / 10000000ULL);
    }
};
} // namespace xboxtls
#endif
