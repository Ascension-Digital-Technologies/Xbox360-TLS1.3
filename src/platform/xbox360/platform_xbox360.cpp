#include "xboxtls/xbox360_platform.h"

#if defined(_XBOX)
#include <string.h>
#include <winsockx.h>
#include "xkelib.h"
#include "syssock.h"

namespace xboxtls {

Error Xbox360Platform::random_bytes(MutableByteSpan out) {
    if (!out.data && out.size)
        return XT_ERR_INVALID_ARGUMENT;
    if (out.size > 0xFFFFFFFFu)
        return XT_ERR_INVALID_ARGUMENT;
    if (out.size)
        XeCryptRandom(out.data, (DWORD)out.size);
    return XT_OK;
}

xt_u64 Xbox360Platform::unix_time_seconds() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    if (u.QuadPart < 116444736000000000ULL)
        return 0;
    return (xt_u64)((u.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

Error xbox360_network_startup() {
    XNetStartupParams xn;
    memset(&xn, 0, sizeof(xn));
    xn.cfgSizeOfStruct = sizeof(xn);
    xn.cfgFlags = 0;
    if (XNetStartup(&xn) != 0)
        return XT_ERR_IO;
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) {
        NetDll_XNetCleanup(XNCALLER_SYSAPP);
        return XT_ERR_IO;
    }
    return XT_OK;
}
void xbox360_network_cleanup() {
    WSACleanup();
    NetDll_XNetCleanup(XNCALLER_SYSAPP);
}

Xbox360SocketStream::Xbox360SocketStream() : socket_(INVALID_SOCKET) {}
Xbox360SocketStream::~Xbox360SocketStream() {
    close();
}
bool Xbox360SocketStream::is_open() const {
    return socket_ != INVALID_SOCKET;
}

Error Xbox360SocketStream::connect_tcp(const char* hostname, xt_u16 port) {
    if (!hostname || !*hostname)
        return XT_ERR_INVALID_ARGUMENT;
    close();
    XNDNS* dns = 0;
    int dns_result = NetDll_XNetDnsLookup(XNCALLER_SYSAPP, hostname, 0, &dns);
    if (dns_result != 0 || !dns)
        return XT_ERR_IO;

    while (dns->iStatus == WSAEINPROGRESS)
        Sleep(1);

    if (dns->iStatus != 0 || dns->cina == 0) {
        NetDll_XNetDnsRelease(XNCALLER_SYSAPP, dns);
        return XT_ERR_IO;
    }

    IN_ADDR resolved = dns->aina[0];
    NetDll_XNetDnsRelease(XNCALLER_SYSAPP, dns);

    socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == INVALID_SOCKET)
        return XT_ERR_IO;
    sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr = resolved;
    if (::connect(socket_, (sockaddr*)&a, sizeof(a)) == SOCKET_ERROR) {
        close();
        return XT_ERR_IO;
    }
    return XT_OK;
}
Error Xbox360SocketStream::send_all(ByteSpan data) {
    if (socket_ == INVALID_SOCKET || (!data.data && data.size))
        return XT_ERR_INVALID_ARGUMENT;
    size_t off = 0;
    while (off < data.size) {
        int chunk = (data.size - off > 0x7fffffffU) ? 0x7fffffff : (int)(data.size - off);
        int n = ::send(socket_, (const char*)data.data + off, chunk, 0);
        if (n <= 0)
            return XT_ERR_IO;
        off += (size_t)n;
    }
    return XT_OK;
}
Error Xbox360SocketStream::recv_some(MutableByteSpan buffer, size_t* received) {
    if (!received || socket_ == INVALID_SOCKET || (!buffer.data && buffer.size))
        return XT_ERR_INVALID_ARGUMENT;
    *received = 0;
    if (!buffer.size)
        return XT_OK;
    int cap = buffer.size > 0x7fffffffU ? 0x7fffffff : (int)buffer.size;
    int n = ::recv(socket_, (char*)buffer.data, cap, 0);
    if (n == 0)
        return XT_ERR_CLOSED;
    if (n < 0)
        return XT_ERR_IO;
    *received = (size_t)n;
    return XT_OK;
}
void Xbox360SocketStream::close() {
    if (socket_ != INVALID_SOCKET) {
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
    }
}

} // namespace xboxtls
#endif
