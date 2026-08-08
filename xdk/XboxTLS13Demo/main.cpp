#include "xboxtls/xboxtls.h"

#if defined(_XBOX)

#include <stdio.h>
#include <string.h>

using namespace xboxtls;

int main() {
    XboxTlsClient client;

    Error error = client.initialize();
    if (error != XT_OK) {
        printf("XboxTLS: initialization failed: %d\n", (int)error);
        return 1;
    }

    error = client.connect("example.com");
    if (error != XT_OK) {
        printf("XboxTLS: TLS connection failed: %d alert=%u/%u\n",
               (int)error,
               (unsigned)client.last_alert_level(),
               (unsigned)client.last_alert_description());
        return 1;
    }

    const char request[] =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: XboxTLS13/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n";

    error = client.send(request, sizeof(request) - 1);

    if (error != XT_OK) {
        printf("XboxTLS: send failed: %d\n", (int)error);
        return 1;
    }

    xt_u8 buffer[1024];

    for (;;) {
        size_t received = 0;
        error = client.receive(buffer, sizeof(buffer), &received);

        if (error == XT_ERR_CLOSED)
            break;

        if (error != XT_OK) {
            printf("XboxTLS: receive failed: %d\n", (int)error);
            return 1;
        }

        if (received)
            fwrite(buffer, 1, received, stdout);
    }

    client.close();
    return 0;
}

#else

int main() {
    return 0;
}

#endif
