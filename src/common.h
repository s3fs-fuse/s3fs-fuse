#ifndef S3FS_COMMON_H_
#define S3FS_COMMON_H_

//
// Macro
//
#define SYSLOGINFO(...) syslog(LOG_INFO, __VA_ARGS__);
#define SYSLOGERR(...)  syslog(LOG_ERR, __VA_ARGS__);
#define SYSLOGCRIT(...) syslog(LOG_CRIT, __VA_ARGS__);

#define SYSLOGDBG(...) \
        if(debug){ \
          syslog(LOG_DEBUG, __VA_ARGS__); \
        }

#define SYSLOGDBGERR(...) \
        if(debug){ \
          syslog(LOG_ERR, __VA_ARGS__); \
        }

#define FGPRINT(...) \
       if(foreground){ \
          printf(__VA_ARGS__); \
       }

//
// Typedef
//
typedef std::map<std::string, std::string> headers_t;

//
// Global valiables
//
extern bool debug;
extern bool foreground;
extern int retries;
extern long connect_timeout;
extern time_t readwrite_timeout;
extern std::string AWSAccessKeyId;
extern std::string AWSSecretAccessKey;
extern std::string program_name;
extern std::string ssl_verify_hostname;
extern std::string service_path;
extern std::string host;
extern std::string bucket;
extern std::string public_bucket;
extern std::string mount_prefix;

#endif // S3FS_COMMON_H_
