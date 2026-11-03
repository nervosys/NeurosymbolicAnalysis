#include <iostream>
#include <cstring>

union Overlay { int i; float f; };

int classify(int x) {
    int r = 0;
    switch (x) {
        case 1:
            r = 010;
        case 2:
            r = 2;
            break;
    }
    if (r > 0)
        std::cout << r;
    void *p = (void *)&r;
    int *q = reinterpret_cast<int *>(p);
    if (q) { goto done; }
done:
    return r;
}
