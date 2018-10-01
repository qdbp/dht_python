#include "util.h"
#include <stdlib.h>

u64 randint(u64 mn, u64 mx) {
    return mn + rand() / (RAND_MAX / (mx - mn + 1) + 1);
}
