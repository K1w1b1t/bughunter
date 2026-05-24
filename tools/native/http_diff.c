#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("{\"module\":\"c_http_diff\",\"error\":\"usage: http_diff <a> <b>\"}\n");
        return 0;
    }
    const char *a = argv[1];
    const char *b = argv[2];
    int la = (int)strlen(a);
    int lb = (int)strlen(b);
    int delta = la > lb ? la - lb : lb - la;
    printf("{\"module\":\"c_http_diff\",\"len_a\":%d,\"len_b\":%d,\"delta\":%d}\n", la, lb, delta);
    return 0;
}
