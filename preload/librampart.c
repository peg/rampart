/*
 * Copyright 2026 The Rampart Authors
 * Licensed under the Apache License, Version 2.0
 *
 * librampart.c — LD_PRELOAD interceptor for Rampart policy engine
 *
 * Intercepts exec-family syscalls and consults rampart serve before execution.
 * Fails open if the policy server is unreachable.
 *
 * Design constraints:
 *   - Single dependency: libcurl (+ pthreads, libc, libdl)
 *   - < 600 lines, auditable in one sitting
 *   - Thread-safe: mutex-protected curl handle, pthread_once init
 *   - Fail-open on every error path
 *   - Persistent HTTP keep-alive connection for < 3ms p99 latency
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <curl/curl.h>

#include <spawn.h>

// Configuration from environment variables
static struct {
    char *url;
    char *token;
    char *mode;
    int fail_open;
    int debug;
    char *agent;
    char *session;
} config;

// HTTP response buffer
struct http_response {
    char *data;
    size_t size;
};

// Global state
static CURL *curl_handle = NULL;
static pthread_mutex_t curl_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;

// Original function pointers
static int (*real_execve)(const char *, char *const[], char *const[]) = NULL;
static int (*real_execvp)(const char *, char *const[]) = NULL;
#ifdef __linux__
static int (*real_execvpe)(const char *, char *const[], char *const[]) = NULL;
#endif
static int (*real_system)(const char *) = NULL;
static FILE *(*real_popen)(const char *, const char *) = NULL;
static int (*real_posix_spawn)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                               const posix_spawnattr_t *, char *const[], char *const[]) = NULL;

static void debug_log(const char *fmt, ...) {
    if (!config.debug) return;
    
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[rampart] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

/* libcurl write callback — appends chunk to a growable http_response buffer. */
static size_t write_callback(void *contents, size_t size, size_t nmemb, struct http_response *response) {
    size_t total_size = size * nmemb;
    char *ptr = realloc(response->data, response->size + total_size + 1);
    if (!ptr) {
        debug_log("Failed to allocate memory for HTTP response");
        return 0;
    }
    
    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, total_size);
    response->size += total_size;
    response->data[response->size] = 0;
    
    return total_size;
}

static void init_config(void) {
    config.url = getenv("RAMPART_URL");
    if (!config.url) config.url = "http://127.0.0.1:19090";
    
    config.token = getenv("RAMPART_TOKEN");
    config.mode = getenv("RAMPART_MODE");
    if (!config.mode) config.mode = "enforce";
    
    char *fail_open_str = getenv("RAMPART_FAIL_OPEN");
    config.fail_open = (!fail_open_str || strcmp(fail_open_str, "1") == 0) ? 1 : 0;
    
    char *debug_str = getenv("RAMPART_DEBUG");
    config.debug = (debug_str && strcmp(debug_str, "1") == 0) ? 1 : 0;
    
    config.agent = getenv("RAMPART_AGENT");
    if (!config.agent) config.agent = "preload";
    
    config.session = getenv("RAMPART_SESSION");
    if (!config.session) {
        static char session_buf[64];
        snprintf(session_buf, sizeof(session_buf), "preload-%d", getpid());
        config.session = session_buf;
    }
}

static void init_library(void) {
    init_config();
    debug_log("Initializing librampart for PID %d", getpid());
    
    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl_handle = curl_easy_init();
    if (!curl_handle) {
        debug_log("Failed to initialize curl handle");
        return;
    }
    
    // Configure persistent keep-alive connection
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 2L);
    curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_TCP_KEEPIDLE, 30L);
    curl_easy_setopt(curl_handle, CURLOPT_TCP_KEEPINTVL, 10L);
    curl_easy_setopt(curl_handle, CURLOPT_FORBID_REUSE, 0L);
    
    // Load original function pointers using union to avoid pedantic warnings
    union { void *p; int (*execve)(const char *, char *const[], char *const[]); } u_execve;
    union { void *p; int (*execvp)(const char *, char *const[]); } u_execvp;
#ifdef __linux__
    union { void *p; int (*execvpe)(const char *, char *const[], char *const[]); } u_execvpe;
#endif
    union { void *p; int (*system)(const char *); } u_system;
    union { void *p; FILE *(*popen)(const char *, const char *); } u_popen;
    union { void *p; int (*posix_spawn)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                                       const posix_spawnattr_t *, char *const[], char *const[]); } u_posix_spawn;
    
    u_execve.p = dlsym(RTLD_NEXT, "execve");
    real_execve = u_execve.execve;
    
    u_execvp.p = dlsym(RTLD_NEXT, "execvp");
    real_execvp = u_execvp.execvp;
    
#ifdef __linux__
    u_execvpe.p = dlsym(RTLD_NEXT, "execvpe");
    real_execvpe = u_execvpe.execvpe;
#endif
    
    u_system.p = dlsym(RTLD_NEXT, "system");
    real_system = u_system.system;
    
    u_popen.p = dlsym(RTLD_NEXT, "popen");
    real_popen = u_popen.popen;
    
    u_posix_spawn.p = dlsym(RTLD_NEXT, "posix_spawn");
    real_posix_spawn = u_posix_spawn.posix_spawn;
    
    if (!real_execve || !real_execvp || !real_system || !real_popen || !real_posix_spawn) {
        debug_log("Failed to load original function pointers");
    }
    
    debug_log("Library initialized successfully");
}

/* Wrap str in quotes with JSON escaping.  Returns a malloc'd string.
 * Allocation: len*2 (worst case: every char needs a backslash) + 2 (quotes) + 1 (NUL). */
static char *escape_json_string(const char *str) {
    if (!str) return strdup("null");

    size_t len = strlen(str);
    char *escaped = malloc(len * 2 + 3);
    if (!escaped) return NULL;
    
    char *p = escaped;
    *p++ = '"';
    
    for (size_t i = 0; i < len; i++) {
        switch (str[i]) {
            case '"': *p++ = '\\'; *p++ = '"'; break;
            case '\\': *p++ = '\\'; *p++ = '\\'; break;
            case '\n': *p++ = '\\'; *p++ = 'n'; break;
            case '\r': *p++ = '\\'; *p++ = 'r'; break;
            case '\t': *p++ = '\\'; *p++ = 't'; break;
            default: *p++ = str[i]; break;
        }
    }
    
    *p++ = '"';
    *p = '\0';
    
    return escaped;
}

/* Build a single command string from argv by joining with spaces.
 * Uses pointer arithmetic instead of strcat to avoid O(n²) rescanning. */
static char *build_command_string(char *const argv[]) {
    if (!argv || !argv[0]) return strdup("");

    /* First pass: measure total length. */
    size_t total_len = 0;
    for (int i = 0; argv[i]; i++) {
        if (i > 0) total_len++;          /* space separator */
        total_len += strlen(argv[i]);
    }

    char *cmd = malloc(total_len + 1);
    if (!cmd) return NULL;

    /* Second pass: copy with a running pointer. */
    char *p = cmd;
    for (int i = 0; argv[i]; i++) {
        if (i > 0) *p++ = ' ';
        size_t len = strlen(argv[i]);
        memcpy(p, argv[i], len);
        p += len;
    }
    *p = '\0';

    return cmd;
}

static int check_policy(const char *command) {
    pthread_once(&init_once, init_library);
    
    if (!curl_handle || !command) {
        debug_log("Curl handle not initialized or command is null");
        return config.fail_open;
    }
    
    if (strcmp(config.mode, "disabled") == 0) {
        debug_log("Rampart disabled, allowing command");
        return 1;
    }
    
    // Build JSON payload manually
    char *escaped_cmd = escape_json_string(command);
    if (!escaped_cmd) {
        debug_log("Failed to escape command string");
        return config.fail_open;
    }
    
    /* Payload: {"agent":"<agent>","session":"<session>","params":{"command":<escaped>}}
     * Fixed overhead: ~50 bytes of JSON skeleton + agent + session strings. */
    size_t payload_size = strlen(escaped_cmd) + strlen(config.agent)
                        + strlen(config.session) + 64;
    char *json_payload = malloc(payload_size);
    if (!json_payload) {
        free(escaped_cmd);
        debug_log("Failed to allocate memory for JSON payload");
        return config.fail_open;
    }

    snprintf(json_payload, payload_size,
        "{\"agent\":\"%s\",\"session\":\"%s\",\"params\":{\"command\":%s}}",
        config.agent, config.session, escaped_cmd);
    
    free(escaped_cmd);
    
    struct http_response response = { .data = NULL, .size = 0 };
    char url[512];
    snprintf(url, sizeof(url), "%s/v1/preflight/exec", config.url);
    
    struct curl_slist *headers = NULL;
    char auth_header[512] = {0};
    
    if (config.token) {
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", config.token);
        headers = curl_slist_append(headers, auth_header);
    }
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    pthread_mutex_lock(&curl_mutex);
    
    curl_easy_setopt(curl_handle, CURLOPT_URL, url);
    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, strlen(json_payload));
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &response);
    
    debug_log("Checking policy for command: %s", command);
    
    CURLcode res = curl_easy_perform(curl_handle);
    
    pthread_mutex_unlock(&curl_mutex);
    
    curl_slist_free_all(headers);
    free(json_payload);
    
    if (res != CURLE_OK) {
        debug_log("HTTP request failed: %s", curl_easy_strerror(res));
        if (response.data) free(response.data);
        return config.fail_open;
    }
    
    long response_code;
    curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &response_code);
    
    if (response_code != 200) {
        debug_log("HTTP request returned %ld", response_code);
        if (response.data) free(response.data);
        return config.fail_open;
    }
    
    /* Parse response — look for "allowed":true / "allowed":false.
     * Also handles "allowed": true (with whitespace) for robustness. */
    int allowed = config.fail_open;
    if (response.data) {
        if (strstr(response.data, "\"allowed\":true")
         || strstr(response.data, "\"allowed\": true")) {
            allowed = 1;
        } else if (strstr(response.data, "\"allowed\":false")
                || strstr(response.data, "\"allowed\": false")) {
            allowed = 0;
        }
        free(response.data);
    }
    
    debug_log("Policy check result: %s", allowed ? "ALLOW" : "DENY");
    
    if (strcmp(config.mode, "monitor") == 0) {
        debug_log("Monitor mode - logging but not blocking");
        return 1;
    }
    
    return allowed;
}

// Intercepted functions
int execve(const char *path, char *const argv[], char *const envp[]) {
    pthread_once(&init_once, init_library);
    
    if (!real_execve) {
        errno = ENOSYS;
        return -1;
    }
    
    char *cmd = build_command_string(argv);
    if (cmd && !check_policy(cmd)) {
        debug_log("Blocking execve: %s", cmd);
        free(cmd);
        errno = EPERM;
        return -1;
    }
    
    debug_log("Allowing execve: %s", cmd ? cmd : "(null)");
    if (cmd) free(cmd);
    return real_execve(path, argv, envp);
}

int execvp(const char *file, char *const argv[]) {
    pthread_once(&init_once, init_library);
    
    if (!real_execvp) {
        errno = ENOSYS;
        return -1;
    }
    
    char *cmd = build_command_string(argv);
    if (cmd && !check_policy(cmd)) {
        debug_log("Blocking execvp: %s", cmd);
        free(cmd);
        errno = EPERM;
        return -1;
    }
    
    debug_log("Allowing execvp: %s", cmd ? cmd : "(null)");
    if (cmd) free(cmd);
    return real_execvp(file, argv);
}

#ifdef __linux__
int execvpe(const char *file, char *const argv[], char *const envp[]) {
    pthread_once(&init_once, init_library);
    
    if (!real_execvpe) {
        errno = ENOSYS;
        return -1;
    }
    
    char *cmd = build_command_string(argv);
    if (cmd && !check_policy(cmd)) {
        debug_log("Blocking execvpe: %s", cmd);
        free(cmd);
        errno = EPERM;
        return -1;
    }
    
    debug_log("Allowing execvpe: %s", cmd ? cmd : "(null)");
    if (cmd) free(cmd);
    return real_execvpe(file, argv, envp);
}
#endif

int system(const char *command) {
    pthread_once(&init_once, init_library);
    
    if (!real_system) {
        errno = ENOSYS;
        return -1;
    }
    
    if (command && !check_policy(command)) {
        debug_log("Blocking system: %s", command);
        errno = EPERM;
        return -1;
    }
    
    debug_log("Allowing system: %s", command ? command : "(null)");
    return real_system(command);
}

FILE *popen(const char *command, const char *type) {
    pthread_once(&init_once, init_library);
    
    if (!real_popen) {
        errno = ENOSYS;
        return NULL;
    }
    
    if (command && !check_policy(command)) {
        debug_log("Blocking popen: %s", command);
        errno = EPERM;
        return NULL;
    }
    
    debug_log("Allowing popen: %s", command ? command : "(null)");
    return real_popen(command, type);
}

int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *file_actions,
                const posix_spawnattr_t *attrp,
                char *const argv[], char *const envp[]) {
    pthread_once(&init_once, init_library);
    
    if (!real_posix_spawn) {
        return ENOSYS;
    }
    
    char *cmd = build_command_string(argv);
    if (cmd && !check_policy(cmd)) {
        debug_log("Blocking posix_spawn: %s", cmd);
        free(cmd);
        return EPERM;
    }
    
    debug_log("Allowing posix_spawn: %s", cmd ? cmd : "(null)");
    if (cmd) free(cmd);
    return real_posix_spawn(pid, path, file_actions, attrp, argv, envp);
}

// Cleanup function (called at library unload)
__attribute__((destructor))
void cleanup_library(void) {
    if (curl_handle) {
        curl_easy_cleanup(curl_handle);
        curl_handle = NULL;
    }
    curl_global_cleanup();
}