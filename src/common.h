#ifndef S3FS_COMMON_H_
#define S3FS_COMMON_H_

//
// Macro
//
#define SAFESTRPTR(strptr) (strptr ? strptr : "")

// for debug
#define	FPRINT_NEST_SPACE_0  ""
#define	FPRINT_NEST_SPACE_1  "  "
#define	FPRINT_NEST_SPACE_2  "    "
#define	FPRINT_NEST_CHECK(NEST) \
        (0 == NEST ? FPRINT_NEST_SPACE_0 : 1 == NEST ? FPRINT_NEST_SPACE_1 : FPRINT_NEST_SPACE_2)

#define LOWFPRINT(NEST, ...) \
        printf("%s%s(%d): ", FPRINT_NEST_CHECK(NEST), __func__, __LINE__); \
        printf(__VA_ARGS__); \
        printf("\n"); \

#define FPRINT(NEST, ...) \
        if(foreground){ \
          LOWFPRINT(NEST, __VA_ARGS__); \
        }

#define FPRINT2(NEST, ...) \
        if(foreground2){ \
          LOWFPRINT(NEST, __VA_ARGS__); \
        }

#define LOWSYSLOGPRINT(LEVEL, ...) \
        syslog(LEVEL, __VA_ARGS__);

#define SYSLOGPRINT(LEVEL, ...) \
        if(LEVEL <= LOG_CRIT || debug){ \
          LOWSYSLOGPRINT(LEVEL, __VA_ARGS__); \
        }

#define DPRINT(LEVEL, NEST, ...) \
        FPRINT(NEST, __VA_ARGS__); \
        SYSLOGPRINT(LEVEL, __VA_ARGS__);

#define DPRINT2(LEVEL, ...) \
        FPRINT2(2, __VA_ARGS__); \
        SYSLOGPRINT(LEVEL, __VA_ARGS__);

// print debug message
#define FPRN(...)      FPRINT(0, __VA_ARGS__)
#define FPRNN(...)     FPRINT(1, __VA_ARGS__)
#define FPRNNN(...)    FPRINT(2, __VA_ARGS__)
#define FPRNINFO(...)  FPRINT2(2, __VA_ARGS__)

// print debug message with putting syslog
#define DPRNCRIT(...)  DPRINT(LOG_CRIT, 0, __VA_ARGS__)
#define DPRN(...)      DPRINT(LOG_ERR, 0, __VA_ARGS__)
#define DPRNN(...)     DPRINT(LOG_DEBUG, 1, __VA_ARGS__)
#define DPRNNN(...)    DPRINT(LOG_DEBUG, 2, __VA_ARGS__)
#define DPRNINFO(...)  DPRINT2(LOG_INFO, __VA_ARGS__)

//
// Typedef
//
typedef std::map<std::string, std::string> headers_t;

//
// Global valiables
//
extern bool debug;
extern bool foreground;
extern bool foreground2;
extern bool nomultipart;
extern std::string program_name;
extern std::string service_path;
extern std::string host;
extern std::string bucket;
extern std::string mount_prefix;

#endif // S3FS_COMMON_H_
