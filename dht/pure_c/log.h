#ifndef DHT_LOG_H
#define DHT_LOG_H

#include <stdio.h>

#define LVL_DEBUG 5
#define LVL_INFO 10
#define LVL_WARN 15
#define LVL_ERROR 20

#ifndef LOGLEVEL
#define LOGLEVEL LVL_INFO
#endif

#define DO_LOG(code, msg, ...)                                                 \
    fprintf(stderr, "%s %s:%d: " msg "\n", #code, __func__, __LINE__, ##__VA_ARGS__);  \
    fflush(stderr);

#if LOGLEVEL <= LVL_DEBUG
#define DEBUG(msg, ...) DO_LOG(D, msg, ##__VA_ARGS__)
#else
#define DEBUG(msg, ...)
#endif

#if LOGLEVEL <= LVL_INFO
#define INFO(msg, ...) DO_LOG(I, msg, ##__VA_ARGS__)
#else
#define INFO(msg, ...)
#endif

#if LOGLEVEL <= LVL_WARN
#define WARN(msg, ...) DO_LOG(W, msg, ##__VA_ARGS__)
#else
#define WARN(msg, ...)
#endif

#if LOGLEVEL <= LVL_ERROR
#define ERROR(msg, ...) DO_LOG(E, msg, ##__VA_ARGS__)
#else
#define ERROR(msg, ...)
#endif

#endif // DHT_LOG_H
