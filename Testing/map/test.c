#include "map.h"

int main()
{
    printf("yo\n");
    map_int_t m;
    map_init(&m);
    map_set(&m, "hello", 1);
    int *val = map_get(&m, "yo");
    if(val)
    {
        printf("%d\n", *val);
    }
    else
    {
        printf("Not found\n");
    }
    // map_set(&m, "hello", 2);
    val = map_get(&m, "hello");
    if(val)
    {
        printf("%d\n", *val);
    }
    else
    {
        printf("Not found\n");
    }
    map_set(&m, "yo", 2);
    map_remove(&m, "hello");
    val = map_get(&m, "hello");
    if(val)
    {
        printf("%d\n", *val);
    }
    else
    {
        printf("Not found\n");
    }
    // map_set(&m, "yo", 2);
    val = map_get(&m, "yo");
    if(val)
    {
        printf("%d\n", *val);
    }
    else
    {
        printf("Not found\n");
    }
}