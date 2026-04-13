#ifndef LOGGER_H
#define LOGGER_H

#include <stdint.h>
#include <stdio.h>

// Log levels
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_WARN = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_FATAL = 4
} LogLevel;

// Logger configuration
typedef struct {
    FILE *file;
    LogLevel level;
    const char *filename;
    int enabled;
    int print_to_console;  // Also print to terminal
} Logger;

// Initialize logger with file path and level
int logger_init(const char *log_file, LogLevel level);

// Close logger and flush buffers
void logger_close(void);

// Get current logger instance
Logger* logger_get_instance(void);

// Log message with level
void logger_log(LogLevel level, const char *format, ...);

// Convenience macros
#define LOG_DEBUG(fmt, ...) logger_log(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  logger_log(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  logger_log(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) logger_log(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define LOG_FATAL(fmt, ...) logger_log(LOG_LEVEL_FATAL, fmt, ##__VA_ARGS__)

// Convert log level to string
const char* log_level_to_string(LogLevel level);

#endif
