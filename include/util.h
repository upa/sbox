#ifndef _UTIL_H_
#define _UTIL_H_

extern int verbose;

#define pr_info(fmt, ...) \
        fprintf(stdout, "INFO:%s: " fmt, __func__, ##__VA_ARGS__)


#define pr_warn(fmt, ...) \
         fprintf(stdout, "\x1b[1m\x1b[33m" "WARN:%s:" "\x1b[0m " fmt,    \
                __func__, ##__VA_ARGS__)

#define pr_err(fmt, ...) \
        fprintf(stdout, "\x1b[1m\x1b[31m" "ERRO:%s:" "\x1b[0m " fmt,    \
                __func__, ##__VA_ARGS__)

#define pr_vl(vl, fmt, ...) do {                                        \
                if (vl <= verbose) {                                    \
                        fprintf(stdout, "\x1b[1m\x1b[34m"               \
                                "VERB:%s:\x1b[0m " fmt,                 \
                                __func__, ##__VA_ARGS__);               \
                }                                                       \
        } while(0)

#define pr_v1(fmt, ...) pr_vl(1, fmt, ##__VA_ARGS__)
#define pr_v2(fmt, ...) pr_vl(2, fmt, ##__VA_ARGS__)
#define pr_v3(fmt, ...) pr_vl(3, fmt, ##__VA_ARGS__)

#endif /* _UTIL_H_*/
