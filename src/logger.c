#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

// Global logger instance
static Logger g_logger = {
    .file = NULL,
    .level = LOG_LEVEL_INFO,
    .filename = NULL,
    .enabled = 0,
    .print_to_console = 1  // Default to print to terminal
};

const char* log_level_to_string(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_DEBUG:   return "DEBUG";
        case LOG_LEVEL_INFO:    return "INFO";
        case LOG_LEVEL_WARN:    return "WARN";
        case LOG_LEVEL_ERROR:   return "ERROR";
        case LOG_LEVEL_FATAL:   return "FATAL";
        default:                return "UNKNOWN";
    }
}

Logger* logger_get_instance(void) {
    return &g_logger;
}

int logger_init(const char *log_file, LogLevel level) {
    // Close existing logger if open
    if (g_logger.file != NULL) {
        fclose(g_logger.file);
        g_logger.file = NULL;
    }

    g_logger.level = level;
    g_logger.filename = log_file;

    if (log_file != NULL && strlen(log_file) > 0) {
        g_logger.file = fopen(log_file, "a");
        if (g_logger.file == NULL) {
            fprintf(stderr, "Failed to open log file: %s\n", log_file);
            return -1;
        }
        g_logger.enabled = 1;
        
        // Write session separator
        fprintf(g_logger.file, "\n");
        fprintf(g_logger.file, "============================================================\n");
        fprintf(g_logger.file, "  Protocol Analyzer - New Session Started\n");
        fprintf(g_logger.file, "============================================================\n");
        fflush(g_logger.file);
        
        return 0;
    }

    // No log file specified, disable logging
    g_logger.enabled = 0;
    return 0;
}

void logger_close(void) {
    if (g_logger.file != NULL) {
        fprintf(g_logger.file, "\n--- Session Ended ---\n");
        fclose(g_logger.file);
        g_logger.file = NULL;
        g_logger.enabled = 0;
    }
}

void logger_log(LogLevel level, const char *format, ...) {

    // Get current timestamp
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    // Also print to terminal if enabled
    if (g_logger.print_to_console) {
        va_list args2;
        va_start(args2, format);
        
        // Use stderr for console output
        fprintf(stderr, "[%s] [%s] ", time_str, log_level_to_string(level));
        vfprintf(stderr, format, args2);
        fprintf(stderr, "\n");
        fflush(stderr);
        
        va_end(args2);
    }    
    // Check if logger is enabled and level is sufficient
    if (!g_logger.enabled || level < g_logger.level) {
        return;
    }

    // Format the message
    va_list args;
    va_start(args, format);

    // Write to log file
    fprintf(g_logger.file, "[%s] [%s] ", time_str, log_level_to_string(level));
    vfprintf(g_logger.file, format, args);
    fprintf(g_logger.file, "\n");

    // Flush to ensure data is written
    fflush(g_logger.file);

    va_end(args);
}
