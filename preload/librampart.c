/*
 * Copyright 2026 The Rampart Authors
 * Licensed under the Apache License, Version 2.0
 *
 * librampart.c — LD_PRELOAD interceptor for Rampart policy engine
 *
 * Intercepts exec-family libc calls and consults rampart serve before execution.
 * Transport and server failures follow the configured degraded-mode behavior;
 * authentication, protocol, and local safety failures deny in enforce mode.
 *
 * Design constraints:
 *   - Single dependency: libcurl (+ pthreads, libc, libdl)
 *   - Thread-safe: mutex-protected curl handle, pthread_once init
 *   - Persistent HTTP keep-alive connection for < 3ms p99 latency
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <curl/curl.h>

#include <spawn.h>

#define DEFAULT_RAMPART_URL "http://127.0.0.1:9090"
#define MAX_HTTP_RESPONSE_BYTES (64U * 1024U)
#define MAX_JSON_PAYLOAD_BYTES (1024U * 1024U)
#define MAX_AUTH_TOKEN_BYTES 4096U

#ifdef __APPLE__
#define PRELOAD_ENV_NAME "DYLD_INSERT_LIBRARIES"
#define PRELOAD_AUX_ENV_NAME "DYLD_FORCE_FLAT_NAMESPACE"
#else
#define PRELOAD_ENV_NAME "LD_PRELOAD"
#endif

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
static char *owned_config_url = NULL;
static char *owned_config_token = NULL;
static char *owned_config_mode = NULL;
static char *owned_config_agent = NULL;
static char *owned_config_session = NULL;
static char *trusted_preload_value = NULL;
static int config_initialization_failed = 0;

// HTTP response buffer
struct http_response {
    char *data;
    size_t size;
    int too_large;
    int allocation_failed;
};

// Global state
static CURL *curl_handle = NULL;
static CURL *inherited_curl_handle = NULL;
static pthread_mutex_t curl_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;
static int curl_global_initialized = 0;
static int curl_atfork_registered = 0;
static char preload_lib_path[PATH_MAX];
static int preload_anchor;

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
static int (*real_posix_spawnp)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                                const posix_spawnattr_t *, char *const[], char *const[]) = NULL;
// Per-function interception toggles (1 = pass-through mode).
static int disable_execve_intercept = 0;
static int disable_execvp_intercept = 0;
#ifdef __linux__
static int disable_execvpe_intercept = 0;
#endif
static int disable_system_intercept = 0;
static int disable_popen_intercept = 0;
static int disable_posix_spawn_intercept = 0;
static int disable_posix_spawnp_intercept = 0;

// One-time warning guards for missing symbols.
static int warned_execve_missing = 0;
static int warned_execvp_missing = 0;
#ifdef __linux__
static int warned_execvpe_missing = 0;
#endif
static int warned_system_missing = 0;
static int warned_popen_missing = 0;
static int warned_posix_spawn_missing = 0;
static int warned_posix_spawnp_missing = 0;

static size_t write_callback(void *contents, size_t size, size_t nmemb,
                             struct http_response *response);

static int configure_curl_handle_locked(void) {
    if (curl_handle) return 1;
    curl_handle = curl_easy_init();
    if (!curl_handle) return 0;
    if (curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback) != CURLE_OK ||
        curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 2L) != CURLE_OK ||
        curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 1L) != CURLE_OK ||
        curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1L) != CURLE_OK ||
        curl_easy_setopt(curl_handle, CURLOPT_TCP_KEEPALIVE, 1L) != CURLE_OK ||
        curl_easy_setopt(curl_handle, CURLOPT_TCP_KEEPIDLE, 30L) != CURLE_OK ||
        curl_easy_setopt(curl_handle, CURLOPT_TCP_KEEPINTVL, 10L) != CURLE_OK ||
        curl_easy_setopt(curl_handle, CURLOPT_FORBID_REUSE, 0L) != CURLE_OK ||
        /* Rampart's control request must go directly to its configured
         * endpoint. Inheriting HTTP(S)_PROXY can disclose bearer credentials
         * and intercepted commands to an ambient proxy. */
        curl_easy_setopt(curl_handle, CURLOPT_PROXY, "") != CURLE_OK ||
        curl_easy_setopt(curl_handle, CURLOPT_NOPROXY, "*") != CURLE_OK ||
        curl_easy_setopt(curl_handle, CURLOPT_NETRC, CURL_NETRC_IGNORED) != CURLE_OK ||
        curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 0L) != CURLE_OK ||
        curl_easy_setopt(curl_handle, CURLOPT_MAXREDIRS, 0L) != CURLE_OK ||
#if LIBCURL_VERSION_NUM >= 0x075500
        curl_easy_setopt(curl_handle, CURLOPT_PROTOCOLS_STR, "http,https") != CURLE_OK ||
        curl_easy_setopt(curl_handle, CURLOPT_REDIR_PROTOCOLS_STR, "http,https") != CURLE_OK ||
#else
        curl_easy_setopt(curl_handle, CURLOPT_PROTOCOLS,
                         (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS)) != CURLE_OK ||
        curl_easy_setopt(curl_handle, CURLOPT_REDIR_PROTOCOLS,
                         (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS)) != CURLE_OK ||
#endif
        0) {
        curl_easy_cleanup(curl_handle);
        curl_handle = NULL;
        return 0;
    }
    return 1;
}

static int ensure_curl_handle(void) {
    int ready;
    pthread_mutex_lock(&curl_mutex);
    /* The child-side atfork handler cannot safely call libcurl. Dispose of
     * the inherited connection lazily once normal execution resumes. */
    if (inherited_curl_handle) {
        curl_easy_cleanup(inherited_curl_handle);
        inherited_curl_handle = NULL;
    }
    ready = configure_curl_handle_locked();
    pthread_mutex_unlock(&curl_mutex);
    return ready;
}

static void curl_atfork_prepare(void) {
    pthread_mutex_lock(&curl_mutex);
}

static void curl_atfork_parent(void) {
    pthread_mutex_unlock(&curl_mutex);
}

static void curl_atfork_child(void) {
    /* A persistent easy handle can retain a duplicated keep-alive socket.
     * Never share it between the parent and child after fork. */
    inherited_curl_handle = curl_handle;
    curl_handle = NULL;
    pthread_mutex_unlock(&curl_mutex);
}

static int preload_env_contains(const char *value) {
    if (!value || !*value || !*preload_lib_path) return 0;
    size_t n = strlen(preload_lib_path);
    const char *p = value;
    while (*p) {
        const char *end = strchr(p, ':');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len == n && strncmp(p, preload_lib_path, n) == 0) return 1;
        if (!end) break;
        p = end + 1;
    }
    return 0;
}

static void warn_once_missing_symbol(int *warned, const char *func_name, const char *phase) {
    if (__sync_lock_test_and_set(warned, 1) != 0) return;
    fprintf(stderr,
            "[rampart] warning: failed to resolve %s via dlsym(RTLD_NEXT) during %s; "
            "interception disabled for this function\n",
            func_name, phase);
}

static int ensure_real_execve(void) {
    if (real_execve) return 1;
    union { void *p; int (*execve)(const char *, char *const[], char *const[]); } u;
    u.p = dlsym(RTLD_NEXT, "execve");
    real_execve = u.execve;
    if (!real_execve) {
        warn_once_missing_symbol(&warned_execve_missing, "execve", "runtime");
        return 0;
    }
    return 1;
}

static int ensure_real_execvp(void) {
    if (real_execvp) return 1;
    union { void *p; int (*execvp)(const char *, char *const[]); } u;
    u.p = dlsym(RTLD_NEXT, "execvp");
    real_execvp = u.execvp;
    if (!real_execvp) {
        warn_once_missing_symbol(&warned_execvp_missing, "execvp", "runtime");
        return 0;
    }
    return 1;
}

#ifdef __linux__
static int ensure_real_execvpe(void) {
    if (real_execvpe) return 1;
    union { void *p; int (*execvpe)(const char *, char *const[], char *const[]); } u;
    u.p = dlsym(RTLD_NEXT, "execvpe");
    real_execvpe = u.execvpe;
    if (!real_execvpe) {
        warn_once_missing_symbol(&warned_execvpe_missing, "execvpe", "runtime");
        return 0;
    }
    return 1;
}
#endif

static int ensure_real_system(void) {
    if (real_system) return 1;
    union { void *p; int (*system)(const char *); } u;
    u.p = dlsym(RTLD_NEXT, "system");
    real_system = u.system;
    if (!real_system) {
        warn_once_missing_symbol(&warned_system_missing, "system", "runtime");
        return 0;
    }
    return 1;
}

static int ensure_real_popen(void) {
    if (real_popen) return 1;
    union { void *p; FILE *(*popen)(const char *, const char *); } u;
    u.p = dlsym(RTLD_NEXT, "popen");
    real_popen = u.popen;
    if (!real_popen) {
        warn_once_missing_symbol(&warned_popen_missing, "popen", "runtime");
        return 0;
    }
    return 1;
}

static int ensure_real_posix_spawn(void) {
    if (real_posix_spawn) return 1;
    union { void *p; int (*posix_spawn)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                                       const posix_spawnattr_t *, char *const[], char *const[]); } u;
    u.p = dlsym(RTLD_NEXT, "posix_spawn");
    real_posix_spawn = u.posix_spawn;
    if (!real_posix_spawn) {
        warn_once_missing_symbol(&warned_posix_spawn_missing, "posix_spawn", "runtime");
        return 0;
    }
    return 1;
}

static int ensure_real_posix_spawnp(void) {
    if (real_posix_spawnp) return 1;
    union { void *p; int (*posix_spawnp)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                                        const posix_spawnattr_t *, char *const[], char *const[]); } u;
    u.p = dlsym(RTLD_NEXT, "posix_spawnp");
    real_posix_spawnp = u.posix_spawnp;
    if (!real_posix_spawnp) {
        warn_once_missing_symbol(&warned_posix_spawnp_missing, "posix_spawnp", "runtime");
        return 0;
    }
    return 1;
}

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
    if (nmemb != 0 && size > SIZE_MAX / nmemb) {
        response->too_large = 1;
        return 0;
    }
    size_t total_size = size * nmemb;
    if (response->size > MAX_HTTP_RESPONSE_BYTES ||
        total_size > MAX_HTTP_RESPONSE_BYTES - response->size) {
        response->too_large = 1;
        return 0;
    }
    if (total_size == 0) return 0;
    char *ptr = realloc(response->data, response->size + total_size + 1);
    if (!ptr) {
        response->allocation_failed = 1;
        debug_log("Failed to allocate memory for HTTP response");
        return 0;
    }

    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, total_size);
    response->size += total_size;
    response->data[response->size] = 0;
    
    return total_size;
}

static char *snapshot_config_value(char **owned, const char *value,
                                   const char *fallback, int empty_uses_fallback) {
    const char *source = value;
    if (!source || (empty_uses_fallback && !source[0])) source = fallback;
    if (!source) return NULL;
    *owned = strdup(source);
    if (!*owned) {
        config_initialization_failed = 1;
        return (char *)fallback;
    }
    return *owned;
}

static void init_config(void) {
    config.url = snapshot_config_value(&owned_config_url, getenv("RAMPART_URL"),
                                       DEFAULT_RAMPART_URL, 1);
    config.token = snapshot_config_value(&owned_config_token, getenv("RAMPART_TOKEN"),
                                         NULL, 0);
    config.mode = snapshot_config_value(&owned_config_mode, getenv("RAMPART_MODE"),
                                        "enforce", 1);
    
    char *fail_open_str = getenv("RAMPART_FAIL_OPEN");
    config.fail_open = (!fail_open_str || strcmp(fail_open_str, "1") == 0) ? 1 : 0;
    
    char *debug_str = getenv("RAMPART_DEBUG");
    config.debug = (debug_str && strcmp(debug_str, "1") == 0) ? 1 : 0;
    
    config.agent = snapshot_config_value(&owned_config_agent, getenv("RAMPART_AGENT"),
                                         "preload", 1);

    static char session_buf[64];
    snprintf(session_buf, sizeof(session_buf), "preload-%d", getpid());
    config.session = snapshot_config_value(&owned_config_session, getenv("RAMPART_SESSION"),
                                           session_buf, 1);
}

static void init_library(void) {
    init_config();
    debug_log("Initializing librampart for PID %d", getpid());

    Dl_info info;
    if (dladdr(&preload_anchor, &info) && info.dli_fname) {
        strncpy(preload_lib_path, info.dli_fname, sizeof(preload_lib_path) - 1);
        preload_lib_path[sizeof(preload_lib_path) - 1] = '\0';
    }

    const char *initial_preload = getenv(PRELOAD_ENV_NAME);
    if (*preload_lib_path) {
        size_t initial_len = initial_preload ? strlen(initial_preload) : 0;
        size_t lib_len = strlen(preload_lib_path);
        int already_present = preload_env_contains(initial_preload);
        if (!already_present && initial_len > SIZE_MAX - lib_len - 2) {
            config_initialization_failed = 1;
        } else {
            size_t value_len = already_present
                ? initial_len + 1
                : initial_len + (initial_len ? 1 : 0) + lib_len + 1;
            trusted_preload_value = malloc(value_len);
            if (!trusted_preload_value) {
                config_initialization_failed = 1;
            } else if (already_present) {
                memcpy(trusted_preload_value, initial_preload, value_len);
            } else {
                snprintf(trusted_preload_value, value_len, "%s%s%s",
                         initial_preload ? initial_preload : "",
                         initial_len ? ":" : "", preload_lib_path);
            }
        }
    } else {
        config_initialization_failed = 1;
    }

    // Initialize libcurl
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        debug_log("Failed to initialize libcurl globally");
        return;
    }
    curl_global_initialized = 1;
    if (pthread_atfork(curl_atfork_prepare, curl_atfork_parent, curl_atfork_child) != 0) {
        debug_log("Failed to register fork-safety handlers");
        return;
    }
    curl_atfork_registered = 1;
    if (!configure_curl_handle_locked()) {
        debug_log("Failed to configure curl handle");
        return;
    }

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
    union { void *p; int (*posix_spawnp)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                                        const posix_spawnattr_t *, char *const[], char *const[]); } u_posix_spawnp;
    
    u_execve.p = dlsym(RTLD_NEXT, "execve");
    real_execve = u_execve.execve;
    disable_execve_intercept = (real_execve == NULL);
    if (disable_execve_intercept) {
        warn_once_missing_symbol(&warned_execve_missing, "execve", "library initialization");
    }

    u_execvp.p = dlsym(RTLD_NEXT, "execvp");
    real_execvp = u_execvp.execvp;
    disable_execvp_intercept = (real_execvp == NULL);
    if (disable_execvp_intercept) {
        warn_once_missing_symbol(&warned_execvp_missing, "execvp", "library initialization");
    }
    
#ifdef __linux__
    u_execvpe.p = dlsym(RTLD_NEXT, "execvpe");
    real_execvpe = u_execvpe.execvpe;
    disable_execvpe_intercept = (real_execvpe == NULL);
    if (disable_execvpe_intercept) {
        warn_once_missing_symbol(&warned_execvpe_missing, "execvpe", "library initialization");
    }
#endif
    
    u_system.p = dlsym(RTLD_NEXT, "system");
    real_system = u_system.system;
    disable_system_intercept = (real_system == NULL);
    if (disable_system_intercept) {
        warn_once_missing_symbol(&warned_system_missing, "system", "library initialization");
    }
    
    u_popen.p = dlsym(RTLD_NEXT, "popen");
    real_popen = u_popen.popen;
    disable_popen_intercept = (real_popen == NULL);
    if (disable_popen_intercept) {
        warn_once_missing_symbol(&warned_popen_missing, "popen", "library initialization");
    }
    
    u_posix_spawn.p = dlsym(RTLD_NEXT, "posix_spawn");
    real_posix_spawn = u_posix_spawn.posix_spawn;
    disable_posix_spawn_intercept = (real_posix_spawn == NULL);
    if (disable_posix_spawn_intercept) {
        warn_once_missing_symbol(&warned_posix_spawn_missing, "posix_spawn", "library initialization");
    }

    u_posix_spawnp.p = dlsym(RTLD_NEXT, "posix_spawnp");
    real_posix_spawnp = u_posix_spawnp.posix_spawnp;
    disable_posix_spawnp_intercept = (real_posix_spawnp == NULL);
    if (disable_posix_spawnp_intercept) {
        warn_once_missing_symbol(&warned_posix_spawnp_missing, "posix_spawnp", "library initialization");
    }

    debug_log("Library initialized successfully");
}

static void free_modified_envp(char **env) {
    if (!env) return;
    for (size_t i = 0; env[i]; i++) free(env[i]);
    free(env);
}

static int env_entry_has_name(const char *entry, const char *name) {
    size_t name_len = strlen(name);
    return entry && strncmp(entry, name, name_len) == 0 && entry[name_len] == '=';
}

static int protected_child_env_entry(const char *entry) {
    static const char *const names[] = {
        PRELOAD_ENV_NAME,
        "RAMPART_URL",
        "RAMPART_TOKEN",
        "RAMPART_MODE",
        "RAMPART_FAIL_OPEN",
        "RAMPART_DEBUG",
        "RAMPART_AGENT",
        "RAMPART_SESSION",
#ifdef __APPLE__
        PRELOAD_AUX_ENV_NAME,
#endif
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (env_entry_has_name(entry, names[i])) return 1;
    }
    return 0;
}

static int append_child_env_entry(char **out, size_t *index,
                                  const char *name, const char *value) {
    if (!value) return 1;
    size_t name_len = strlen(name), value_len = strlen(value);
    if (name_len > SIZE_MAX - value_len - 2) return 0;
    size_t entry_len = name_len + value_len + 2;
    out[*index] = malloc(entry_len);
    if (!out[*index]) return 0;
    snprintf(out[*index], entry_len, "%s=%s", name, value);
    (*index)++;
    return 1;
}

/* Rebuild envp for explicit-environment process launches. The loader setting
 * and Rampart control-plane values are snapshots from library initialization,
 * not caller-controlled values from a later execve/posix_spawn envp. */
static char **build_trusted_child_env(char *const envp[], int *modified, int *failed) {
    *modified = 0;
    *failed = 0;
    if (config_initialization_failed || !trusted_preload_value) {
        *failed = 1;
        return (char **)envp;
    }

    size_t kept = 0;
    for (size_t i = 0; envp && envp[i]; i++) {
        if (!protected_child_env_entry(envp[i])) kept++;
    }
    size_t trusted_count = 7 + (config.token ? 1 : 0);
#ifdef __APPLE__
    trusted_count++;
#endif
    if (kept > SIZE_MAX - trusted_count - 1) {
        *failed = 1;
        return (char **)envp;
    }
    char **out = calloc(kept + trusted_count + 1, sizeof(char *));
    if (!out) { *failed = 1; return (char **)envp; }

    size_t index = 0;
    for (size_t i = 0; envp && envp[i]; i++) {
        if (protected_child_env_entry(envp[i])) continue;
        out[index] = strdup(envp[i]);
        if (!out[index]) goto allocation_failure;
        index++;
    }

    if (!append_child_env_entry(out, &index, PRELOAD_ENV_NAME, trusted_preload_value) ||
        !append_child_env_entry(out, &index, "RAMPART_URL", config.url) ||
        !append_child_env_entry(out, &index, "RAMPART_TOKEN", config.token) ||
        !append_child_env_entry(out, &index, "RAMPART_MODE", config.mode) ||
        !append_child_env_entry(out, &index, "RAMPART_FAIL_OPEN", config.fail_open ? "1" : "0") ||
        !append_child_env_entry(out, &index, "RAMPART_DEBUG", config.debug ? "1" : "0") ||
        !append_child_env_entry(out, &index, "RAMPART_AGENT", config.agent) ||
        !append_child_env_entry(out, &index, "RAMPART_SESSION", config.session)
#ifdef __APPLE__
        || !append_child_env_entry(out, &index, PRELOAD_AUX_ENV_NAME, "1")
#endif
    ) {
        goto allocation_failure;
    }
    *modified = 1;
    return out;

allocation_failure:
    free_modified_envp(out);
    *failed = 1;
    return (char **)envp;
}

static int checked_add_size(size_t *total, size_t amount) {
    if (*total > SIZE_MAX - amount) return 0;
    *total += amount;
    return 1;
}

/* Return the byte length of a valid UTF-8 sequence, or zero for an invalid
 * leading byte/sequence. Keeping valid UTF-8 intact preserves command names;
 * invalid path bytes are encoded as JSON \u00XX escapes instead of producing
 * a request that Go's JSON decoder would reject. */
static size_t utf8_sequence_length(const unsigned char *s, size_t remaining) {
    if (remaining == 0) return 0;
    if (s[0] < 0x80) return 1;
    if (s[0] >= 0xc2 && s[0] <= 0xdf && remaining >= 2 &&
        s[1] >= 0x80 && s[1] <= 0xbf) return 2;
    if (s[0] == 0xe0 && remaining >= 3 && s[1] >= 0xa0 && s[1] <= 0xbf &&
        s[2] >= 0x80 && s[2] <= 0xbf) return 3;
    if (((s[0] >= 0xe1 && s[0] <= 0xec) || (s[0] >= 0xee && s[0] <= 0xef)) &&
        remaining >= 3 && s[1] >= 0x80 && s[1] <= 0xbf &&
        s[2] >= 0x80 && s[2] <= 0xbf) return 3;
    if (s[0] == 0xed && remaining >= 3 && s[1] >= 0x80 && s[1] <= 0x9f &&
        s[2] >= 0x80 && s[2] <= 0xbf) return 3;
    if (s[0] == 0xf0 && remaining >= 4 && s[1] >= 0x90 && s[1] <= 0xbf &&
        s[2] >= 0x80 && s[2] <= 0xbf && s[3] >= 0x80 && s[3] <= 0xbf) return 4;
    if (s[0] >= 0xf1 && s[0] <= 0xf3 && remaining >= 4 &&
        s[1] >= 0x80 && s[1] <= 0xbf && s[2] >= 0x80 && s[2] <= 0xbf &&
        s[3] >= 0x80 && s[3] <= 0xbf) return 4;
    if (s[0] == 0xf4 && remaining >= 4 && s[1] >= 0x80 && s[1] <= 0x8f &&
        s[2] >= 0x80 && s[2] <= 0xbf && s[3] >= 0x80 && s[3] <= 0xbf) return 4;
    return 0;
}

/* Wrap str in quotes with strict JSON escaping. Returns a malloc'd string. */
static char *escape_json_string(const char *str) {
    if (!str) return strdup("null");

    size_t len = strlen(str);
    size_t encoded_len = 2;
    for (size_t i = 0; i < len;) {
        unsigned char c = (unsigned char)str[i];
        size_t amount = 1;
        size_t sequence_len = utf8_sequence_length((const unsigned char *)str + i, len - i);
        if (c == '"' || c == '\\') amount = 2;
        else if (c < 0x20 || sequence_len == 0) amount = 6;
        else if (c >= 0x80) amount = sequence_len;
        if (!checked_add_size(&encoded_len, amount)) return NULL;
        i += (c >= 0x80 && sequence_len > 0) ? sequence_len : 1;
    }
    if (!checked_add_size(&encoded_len, 1)) return NULL;
    char *escaped = malloc(encoded_len);
    if (!escaped) return NULL;

    static const char hex[] = "0123456789abcdef";
    char *p = escaped;
    *p++ = '"';

    for (size_t i = 0; i < len;) {
        unsigned char c = (unsigned char)str[i];
        size_t sequence_len = utf8_sequence_length((const unsigned char *)str + i, len - i);
        switch (c) {
            case '"': *p++ = '\\'; *p++ = '"'; break;
            case '\\': *p++ = '\\'; *p++ = '\\'; break;
            default:
                if (c < 0x20 || sequence_len == 0) {
                    *p++ = '\\'; *p++ = 'u'; *p++ = '0'; *p++ = '0';
                    *p++ = hex[c >> 4]; *p++ = hex[c & 0x0f];
                } else if (c >= 0x80) {
                    memcpy(p, str + i, sequence_len);
                    p += sequence_len;
                    i += sequence_len - 1;
                } else {
                    *p++ = (char)c;
                }
                break;
        }
        i++;
    }

    *p++ = '"';
    *p = '\0';

    return escaped;
}

static int shell_safe_byte(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || strchr("_@%+=:,./-", (int)c) != NULL;
}

static size_t shell_word_size(const char *word) {
    if (!word || !word[0]) return 2;
    size_t size = 0;
    int needs_quotes = 0;
    for (const unsigned char *p = (const unsigned char *)word; *p; p++) {
        if (!shell_safe_byte(*p)) needs_quotes = 1;
        if (!checked_add_size(&size, *p == '\'' ? 4 : 1)) return SIZE_MAX;
    }
    if (!needs_quotes) return strlen(word);
    if (!checked_add_size(&size, 2)) return SIZE_MAX;
    return size;
}

static char *append_shell_word(char *out, const char *word) {
    if (!word || !word[0]) {
        *out++ = '\''; *out++ = '\'';
        return out;
    }
    int needs_quotes = 0;
    for (const unsigned char *p = (const unsigned char *)word; *p; p++) {
        if (!shell_safe_byte(*p)) { needs_quotes = 1; break; }
    }
    if (!needs_quotes) {
        size_t len = strlen(word);
        memcpy(out, word, len);
        return out + len;
    }
    *out++ = '\'';
    for (const char *p = word; *p; p++) {
        if (*p == '\'') {
            memcpy(out, "'\\''", 4);
            out += 4;
        } else {
            *out++ = *p;
        }
    }
    *out++ = '\'';
    return out;
}

static const char *command_name(const char *executable, char *const argv[]) {
    if (!executable || !executable[0]) return (argv && argv[0]) ? argv[0] : "";
    if (!argv || !argv[0] || !argv[0][0]) return executable;
    const char *base = strrchr(executable, '/');
    base = base ? base + 1 : executable;
    /* Preserve the familiar argv[0] form ("git", not "/usr/bin/git") when it
     * truthfully names the executable, so existing command policies keep
     * matching. Use the real path when argv[0] tries to disguise the binary. */
    if (strcmp(argv[0], executable) == 0 || strcmp(argv[0], base) == 0) return argv[0];
    return executable;
}

/* Represent argv as an unambiguous POSIX shell-like command. */
static char *build_exec_command(const char *executable, char *const argv[]) {
    const char *first = command_name(executable, argv);
    size_t total_len = shell_word_size(first);
    if (total_len == SIZE_MAX) return NULL;
    for (size_t i = 1; argv && argv[0] && argv[i]; i++) {
        size_t word_len = shell_word_size(argv[i]);
        if (word_len == SIZE_MAX || !checked_add_size(&total_len, 1) ||
            !checked_add_size(&total_len, word_len)) return NULL;
    }
    if (total_len >= MAX_JSON_PAYLOAD_BYTES || !checked_add_size(&total_len, 1)) return NULL;

    char *cmd = malloc(total_len);
    if (!cmd) return NULL;

    char *p = append_shell_word(cmd, first);
    for (size_t i = 1; argv && argv[0] && argv[i]; i++) {
        *p++ = ' ';
        p = append_shell_word(p, argv[i]);
    }
    *p = '\0';
    return cmd;
}

static const char *skip_json_ws(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    return p;
}

static int is_hex_digit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static const char *skip_json_string(const char *p, const char *end) {
    if (p >= end || *p != '"') return NULL;
    p++;
    while (p < end) {
        unsigned char c = (unsigned char)*p++;
        if (c == '"') return p;
        if (c < 0x20) return NULL;
        if (c != '\\') continue;
        if (p >= end) return NULL;
        char escaped = *p++;
        if (strchr("\"\\/bfnrt", escaped)) continue;
        if (escaped != 'u' || end - p < 4 || !is_hex_digit(p[0]) ||
            !is_hex_digit(p[1]) || !is_hex_digit(p[2]) || !is_hex_digit(p[3])) return NULL;
        p += 4;
    }
    return NULL;
}

static const char *skip_json_value(const char *p, const char *end, unsigned depth);

static const char *skip_json_container(const char *p, const char *end, unsigned depth,
                                       char close, int object) {
    if (depth > 32) return NULL;
    p = skip_json_ws(p + 1, end);
    if (p < end && *p == close) return p + 1;
    for (;;) {
        if (object) {
            p = skip_json_string(p, end);
            if (!p) return NULL;
            p = skip_json_ws(p, end);
            if (p >= end || *p++ != ':') return NULL;
        }
        p = skip_json_value(skip_json_ws(p, end), end, depth + 1);
        if (!p) return NULL;
        p = skip_json_ws(p, end);
        if (p >= end) return NULL;
        if (*p == close) return p + 1;
        if (*p++ != ',') return NULL;
        p = skip_json_ws(p, end);
    }
}

static const char *skip_json_number(const char *p, const char *end) {
    if (p < end && *p == '-') p++;
    if (p >= end) return NULL;
    if (*p == '0') p++;
    else {
        if (*p < '1' || *p > '9') return NULL;
        while (p < end && *p >= '0' && *p <= '9') p++;
    }
    if (p < end && *p == '.') {
        p++;
        if (p >= end || *p < '0' || *p > '9') return NULL;
        while (p < end && *p >= '0' && *p <= '9') p++;
    }
    if (p < end && (*p == 'e' || *p == 'E')) {
        p++;
        if (p < end && (*p == '+' || *p == '-')) p++;
        if (p >= end || *p < '0' || *p > '9') return NULL;
        while (p < end && *p >= '0' && *p <= '9') p++;
    }
    return p;
}

static const char *skip_json_value(const char *p, const char *end, unsigned depth) {
    if (p >= end) return NULL;
    if (*p == '"') return skip_json_string(p, end);
    if (*p == '{') return skip_json_container(p, end, depth, '}', 1);
    if (*p == '[') return skip_json_container(p, end, depth, ']', 0);
    if (end - p >= 4 && memcmp(p, "true", 4) == 0) return p + 4;
    if (end - p >= 5 && memcmp(p, "false", 5) == 0) return p + 5;
    if (end - p >= 4 && memcmp(p, "null", 4) == 0) return p + 4;
    return skip_json_number(p, end);
}

/* Parse exactly one top-level allowed boolean. This avoids substring tricks
 * such as an error message containing \"allowed\":true. */
static int parse_allowed_response(const char *data, size_t size, int *allowed) {
    if (!data || !allowed) return 0;
    const char *p = skip_json_ws(data, data + size);
    const char *end = data + size;
    if (p >= end || *p++ != '{') return 0;
    p = skip_json_ws(p, end);
    int found = 0;
    if (p < end && *p == '}') return 0;
    for (;;) {
        const char *key_start = p;
        const char *key_end = skip_json_string(p, end);
        if (!key_end) return 0;
        int is_allowed = key_end - key_start == 9 && memcmp(key_start, "\"allowed\"", 9) == 0;
        p = skip_json_ws(key_end, end);
        if (p >= end || *p++ != ':') return 0;
        p = skip_json_ws(p, end);
        if (is_allowed) {
            if (found) return 0;
            if (end - p >= 4 && memcmp(p, "true", 4) == 0) {
                *allowed = 1;
                p += 4;
            } else if (end - p >= 5 && memcmp(p, "false", 5) == 0) {
                *allowed = 0;
                p += 5;
            } else {
                return 0;
            }
            found = 1;
        } else {
            p = skip_json_value(p, end, 0);
            if (!p) return 0;
        }
        p = skip_json_ws(p, end);
        if (p >= end) return 0;
        if (*p == '}') {
            p = skip_json_ws(p + 1, end);
            return found && p == end;
        }
        if (*p++ != ',') return 0;
        p = skip_json_ws(p, end);
    }
}

static int monitor_mode(void) {
    return config.mode && strcmp(config.mode, "monitor") == 0;
}

static int recoverable_failure_result(void) {
    return monitor_mode() || config.fail_open;
}

static int safety_failure_result(void) {
    return monitor_mode() || (config.mode && strcmp(config.mode, "disabled") == 0);
}

static int safe_http_endpoint(const char *url) {
    if (!url) return 0;
    const char *authority;
    if (strncasecmp(url, "http://", 7) == 0) authority = url + 7;
    else if (strncasecmp(url, "https://", 8) == 0) authority = url + 8;
    else return 0;

    const char *authority_end = authority;
    while (*authority_end && *authority_end != '/') authority_end++;
    size_t authority_len = (size_t)(authority_end - authority);
    if (authority_len == 0 || memchr(authority, '@', authority_len)) {
        return 0;
    }
    if (*authority == '[') {
        const char *close = memchr(authority + 1, ']', authority_len - 1);
        if (!close || close == authority + 1 ||
            (close + 1 != authority_end && close[1] != ':')) return 0;
        if (close + 1 < authority_end && close + 2 == authority_end) return 0;
    } else {
        const char *colon = memchr(authority, ':', authority_len);
        size_t host_len = colon ? (size_t)(colon - authority) : authority_len;
        if (host_len == 0) return 0;
        if (colon && (colon + 1 == authority_end ||
                      memchr(colon + 1, ':', (size_t)(authority_end - colon - 1)))) return 0;
    }
    for (const unsigned char *p = (const unsigned char *)authority; *p; p++) {
        if (*p <= 0x20 || *p == 0x7f || *p == '\\' || *p == '?' || *p == '#') return 0;
    }
    return 1;
}

static int is_transport_failure(CURLcode result) {
    switch (result) {
        case CURLE_COULDNT_RESOLVE_PROXY:
        case CURLE_COULDNT_RESOLVE_HOST:
        case CURLE_COULDNT_CONNECT:
        case CURLE_PARTIAL_FILE:
        case CURLE_OPERATION_TIMEDOUT:
        case CURLE_SSL_CONNECT_ERROR:
        case CURLE_GOT_NOTHING:
        case CURLE_SEND_ERROR:
        case CURLE_RECV_ERROR:
        case CURLE_PEER_FAILED_VERIFICATION:
            return 1;
        default:
            return 0;
    }
}

static int check_policy(const char *command) {
    pthread_once(&init_once, init_library);

    if (strcmp(config.mode, "disabled") == 0) {
        debug_log("Rampart disabled, allowing command");
        return 1;
    }

    if (config_initialization_failed) {
        debug_log("Rampart configuration could not be initialized safely");
        return safety_failure_result();
    }
    if (!safe_http_endpoint(config.url)) {
        debug_log("RAMPART_URL is not a safe absolute HTTP(S) endpoint");
        return safety_failure_result();
    }
    if (!curl_atfork_registered) {
        debug_log("Fork-safety handlers are unavailable");
        return safety_failure_result();
    }
    if (!ensure_curl_handle()) {
        debug_log("Curl handle is unavailable");
        return safety_failure_result();
    }
    if (!command) {
        debug_log("Command is null");
        return safety_failure_result();
    }
    if (strlen(command) >= MAX_JSON_PAYLOAD_BYTES ||
        strlen(config.agent) >= MAX_JSON_PAYLOAD_BYTES ||
        strlen(config.session) >= MAX_JSON_PAYLOAD_BYTES) {
        debug_log("Policy request input exceeds the maximum payload size");
        return safety_failure_result();
    }

    char *escaped_cmd = escape_json_string(command);
    char *escaped_agent = escape_json_string(config.agent);
    char *escaped_session = escape_json_string(config.session);
    if (!escaped_cmd || !escaped_agent || !escaped_session) {
        free(escaped_cmd);
        free(escaped_agent);
        free(escaped_session);
        debug_log("Failed to encode policy request");
        return safety_failure_result();
    }

    static const char payload_format[] =
        "{\"agent\":%s,\"session\":%s,\"params\":{\"command\":%s},\"enforce\":true}";
    int payload_len = snprintf(NULL, 0, payload_format,
                               escaped_agent, escaped_session, escaped_cmd);
    if (payload_len < 0 || (size_t)payload_len >= MAX_JSON_PAYLOAD_BYTES) {
        free(escaped_cmd);
        free(escaped_agent);
        free(escaped_session);
        debug_log("Encoded policy request exceeds the maximum payload size");
        return safety_failure_result();
    }
    char *json_payload = malloc((size_t)payload_len + 1);
    if (!json_payload) {
        free(escaped_cmd);
        free(escaped_agent);
        free(escaped_session);
        debug_log("Failed to allocate policy request");
        return safety_failure_result();
    }
    snprintf(json_payload, (size_t)payload_len + 1, payload_format,
             escaped_agent, escaped_session, escaped_cmd);
    free(escaped_cmd);
    free(escaped_agent);
    free(escaped_session);

    const char endpoint[] = "/v1/preflight/exec";
    size_t base_len = strlen(config.url);
    while (base_len > 0 && config.url[base_len - 1] == '/') base_len--;
    size_t url_len = base_len;
    if (!checked_add_size(&url_len, sizeof(endpoint))) {
        free(json_payload);
        return safety_failure_result();
    }
    char *url = malloc(url_len);
    if (!url) {
        free(json_payload);
        return safety_failure_result();
    }
    memcpy(url, config.url, base_len);
    memcpy(url + base_len, endpoint, sizeof(endpoint));

    struct http_response response = { .data = NULL, .size = 0,
                                      .too_large = 0, .allocation_failed = 0 };
    struct curl_slist *headers = NULL;
    char *auth_header = NULL;

    if (config.token && config.token[0]) {
        static const char auth_prefix[] = "Authorization: Bearer ";
        size_t token_len = strlen(config.token);
        if (token_len > MAX_AUTH_TOKEN_BYTES || strchr(config.token, '\r') ||
            strchr(config.token, '\n')) {
            debug_log("Invalid RAMPART_TOKEN value");
            free(url);
            free(json_payload);
            return safety_failure_result();
        }
        size_t auth_len = sizeof(auth_prefix) - 1 + token_len + 1;
        auth_header = malloc(auth_len);
        if (!auth_header) {
            free(url);
            free(json_payload);
            return safety_failure_result();
        }
        snprintf(auth_header, auth_len, "%s%s", auth_prefix, config.token);
        headers = curl_slist_append(NULL, auth_header);
        if (!headers) {
            free(auth_header);
            free(url);
            free(json_payload);
            return safety_failure_result();
        }
    }
    struct curl_slist *new_headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!new_headers) {
        curl_slist_free_all(headers);
        free(auth_header);
        free(url);
        free(json_payload);
        return safety_failure_result();
    }
    headers = new_headers;

    pthread_mutex_lock(&curl_mutex);
    CURLcode setup_result = CURLE_OK;
    if (curl_easy_setopt(curl_handle, CURLOPT_URL, url) != CURLE_OK ||
        curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, json_payload) != CURLE_OK ||
        curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, (long)payload_len) != CURLE_OK ||
        curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &response) != CURLE_OK) {
        setup_result = CURLE_FAILED_INIT;
    }

    debug_log("Checking policy for intercepted command (%zu bytes)", strlen(command));
    CURLcode result = setup_result == CURLE_OK ? curl_easy_perform(curl_handle) : setup_result;
    long response_code = 0;
    if (result == CURLE_OK && curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE,
                                                &response_code) != CURLE_OK) {
        result = CURLE_FAILED_INIT;
    }
    /* libcurl retains these pointers; clear them before releasing the shared
     * handle and freeing request-local storage. */
    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, NULL);
    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, 0L);
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, NULL);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, NULL);
    pthread_mutex_unlock(&curl_mutex);

    curl_slist_free_all(headers);
    free(auth_header);
    free(url);
    free(json_payload);

    if (result != CURLE_OK) {
        debug_log("HTTP request failed: %s", curl_easy_strerror(result));
        free(response.data);
        if (response.too_large || response.allocation_failed || !is_transport_failure(result)) {
            return safety_failure_result();
        }
        return recoverable_failure_result();
    }

    if (response_code != 200) {
        debug_log("HTTP request returned %ld", response_code);
        free(response.data);
        if (response_code >= 500 && response_code <= 599) {
            return recoverable_failure_result();
        }
        return safety_failure_result();
    }

    int allowed = 0;
    if (!parse_allowed_response(response.data, response.size, &allowed)) {
        debug_log("Policy response did not contain one valid top-level allowed boolean");
        free(response.data);
        return safety_failure_result();
    }
    free(response.data);
    debug_log("Policy check result: %s", allowed ? "ALLOW" : "DENY");

    if (monitor_mode()) {
        debug_log("Monitor mode - logging but not blocking");
        return 1;
    }

    return allowed;
}

// Intercepted functions
int execve(const char *path, char *const argv[], char *const envp[]) {
    pthread_once(&init_once, init_library);
    
    if (!ensure_real_execve()) {
        errno = EIO;
        return -1;
    }
    if (disable_execve_intercept) return real_execve(path, argv, envp);
    
    char *cmd = build_exec_command(path, argv);
    int allowed = cmd ? check_policy(cmd) : safety_failure_result();
    if (!allowed) {
        debug_log("Blocking execve (%s)", cmd ? "policy decision" : "command encoding failed");
        free(cmd);
        errno = EPERM;
        return -1;
    }
    
    debug_log("Allowing execve");
    if (cmd) free(cmd);
    int modified = 0, cascade_failed = 0;
    char **effective_envp = build_trusted_child_env(envp, &modified, &cascade_failed);
    if (cascade_failed && !safety_failure_result()) {
        debug_log("Blocking execve because preload cascade could not be preserved");
        errno = EPERM;
        return -1;
    }
    int rc = real_execve(path, argv, effective_envp);
    if (modified) free_modified_envp(effective_envp);
    return rc;
}

int execvp(const char *file, char *const argv[]) {
    pthread_once(&init_once, init_library);
    
    if (!ensure_real_execvp()) {
        errno = EIO;
        return -1;
    }
    if (disable_execvp_intercept) return real_execvp(file, argv);
    
    char *cmd = build_exec_command(file, argv);
    int allowed = cmd ? check_policy(cmd) : safety_failure_result();
    if (!allowed) {
        debug_log("Blocking execvp (%s)", cmd ? "policy decision" : "command encoding failed");
        free(cmd);
        errno = EPERM;
        return -1;
    }
    
    debug_log("Allowing execvp");
    if (cmd) free(cmd);
    return real_execvp(file, argv);
}

#ifdef __linux__
int execvpe(const char *file, char *const argv[], char *const envp[]) {
    pthread_once(&init_once, init_library);
    
    if (!ensure_real_execvpe()) {
        errno = EIO;
        return -1;
    }
    if (disable_execvpe_intercept) return real_execvpe(file, argv, envp);
    
    char *cmd = build_exec_command(file, argv);
    int allowed = cmd ? check_policy(cmd) : safety_failure_result();
    if (!allowed) {
        debug_log("Blocking execvpe (%s)", cmd ? "policy decision" : "command encoding failed");
        free(cmd);
        errno = EPERM;
        return -1;
    }
    
    debug_log("Allowing execvpe");
    if (cmd) free(cmd);
    int modified = 0, cascade_failed = 0;
    char **effective_envp = build_trusted_child_env(envp, &modified, &cascade_failed);
    if (cascade_failed && !safety_failure_result()) {
        debug_log("Blocking execvpe because preload cascade could not be preserved");
        errno = EPERM;
        return -1;
    }
    int rc = real_execvpe(file, argv, effective_envp);
    if (modified) free_modified_envp(effective_envp);
    return rc;
}
#endif

int system(const char *command) {
    pthread_once(&init_once, init_library);
    
    if (!ensure_real_system()) {
        errno = EIO;
        return -1;
    }
    if (disable_system_intercept) return real_system(command);
    
    if (command && !check_policy(command)) {
        debug_log("Blocking system (policy decision)");
        errno = EPERM;
        return -1;
    }
    
    debug_log("Allowing system");
    return real_system(command);
}

FILE *popen(const char *command, const char *type) {
    pthread_once(&init_once, init_library);
    
    if (!ensure_real_popen()) {
        errno = EIO;
        return NULL;
    }
    if (disable_popen_intercept) return real_popen(command, type);
    
    if (command && !check_policy(command)) {
        debug_log("Blocking popen (policy decision)");
        errno = EPERM;
        return NULL;
    }
    
    debug_log("Allowing popen");
    return real_popen(command, type);
}

int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *file_actions,
                const posix_spawnattr_t *attrp,
                char *const argv[], char *const envp[]) {
    pthread_once(&init_once, init_library);
    
    if (!ensure_real_posix_spawn()) {
        return EIO;
    }
    if (disable_posix_spawn_intercept) {
        return real_posix_spawn(pid, path, file_actions, attrp, argv, envp);
    }
    
    char *cmd = build_exec_command(path, argv);
    int allowed = cmd ? check_policy(cmd) : safety_failure_result();
    if (!allowed) {
        debug_log("Blocking posix_spawn (%s)", cmd ? "policy decision" : "command encoding failed");
        free(cmd);
        return EPERM;
    }
    
    debug_log("Allowing posix_spawn");
    if (cmd) free(cmd);
    int modified = 0, cascade_failed = 0;
    char **effective_envp = build_trusted_child_env(envp, &modified, &cascade_failed);
    if (cascade_failed && !safety_failure_result()) {
        debug_log("Blocking posix_spawn because preload cascade could not be preserved");
        return EPERM;
    }
    int rc = real_posix_spawn(pid, path, file_actions, attrp, argv, effective_envp);
    if (modified) free_modified_envp(effective_envp);
    return rc;
}

int posix_spawnp(pid_t *pid, const char *file,
                 const posix_spawn_file_actions_t *file_actions,
                 const posix_spawnattr_t *attrp,
                 char *const argv[], char *const envp[]) {
    pthread_once(&init_once, init_library);

    if (!ensure_real_posix_spawnp()) return EIO;
    if (disable_posix_spawnp_intercept) {
        return real_posix_spawnp(pid, file, file_actions, attrp, argv, envp);
    }

    char *cmd = build_exec_command(file, argv);
    int allowed = cmd ? check_policy(cmd) : safety_failure_result();
    if (!allowed) {
        debug_log("Blocking posix_spawnp (%s)", cmd ? "policy decision" : "command encoding failed");
        free(cmd);
        return EPERM;
    }

    debug_log("Allowing posix_spawnp");
    free(cmd);
    int modified = 0, cascade_failed = 0;
    char **effective_envp = build_trusted_child_env(envp, &modified, &cascade_failed);
    if (cascade_failed && !safety_failure_result()) {
        debug_log("Blocking posix_spawnp because preload cascade could not be preserved");
        return EPERM;
    }
    int rc = real_posix_spawnp(pid, file, file_actions, attrp, argv, effective_envp);
    if (modified) free_modified_envp(effective_envp);
    return rc;
}

__attribute__((constructor))
static void load_library(void) {
    pthread_once(&init_once, init_library);
}

// Cleanup function (called at library unload)
__attribute__((destructor))
void cleanup_library(void) {
    pthread_mutex_lock(&curl_mutex);
    if (curl_handle) {
        curl_easy_cleanup(curl_handle);
        curl_handle = NULL;
    }
    if (inherited_curl_handle) {
        curl_easy_cleanup(inherited_curl_handle);
        inherited_curl_handle = NULL;
    }
    pthread_mutex_unlock(&curl_mutex);
    if (curl_global_initialized) {
        curl_global_cleanup();
        curl_global_initialized = 0;
    }
    free(owned_config_url);
    free(owned_config_token);
    free(owned_config_mode);
    free(owned_config_agent);
    free(owned_config_session);
    free(trusted_preload_value);
}
