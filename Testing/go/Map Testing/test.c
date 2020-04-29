#include <stdio.h>
#include "include/map.h"

int main()
{
    map_int_t m;
    int *val;
    map_init(&m);
    map_set(&m, "hello", 1);
    map_set(&m, "yo", 2);
    val = map_get(&m, "testkey");
    if (val) {
        printf("value: %d\n", *val);
    } else {
        printf("value not found\n");
    }
    val = map_get(&m, "yo");
    if (val) {
        printf("value: %d\n", *val);
    } else {
        printf("value not found\n");
    }
    map_remove(&m, "hello");
    val = map_get(&m, "hello");
    if (val) {
        printf("value: %d\n", *val);
    } else {
        printf("value not found\n");
    }
    map_deinit(&m);
    return 0;
}