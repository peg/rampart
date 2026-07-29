/*
 * Copyright 2026 The Rampart Authors
 * Licensed under the Apache License, Version 2.0
 */

#include <assert.h>
#include <stdio.h>

/* Keep helper tests in the same translation unit so the production helpers
 * remain private to the preload library. */
#include "librampart.c"

static void test_json_escaping(void) {
    char *escaped = escape_json_string("a\"\\\b\f\n\r\t");
    assert(escaped != NULL);
    assert(strcmp(escaped, "\"a\\\"\\\\\\u0008\\u000c\\u000a\\u000d\\u0009\"") == 0);
    free(escaped);

    escaped = escape_json_string("caf\xc3\xa9");
    assert(escaped != NULL);
    assert(strcmp(escaped, "\"caf\xc3\xa9\"") == 0);
    free(escaped);

    const char invalid_utf8[] = {'x', (char)0xff, '\0'};
    escaped = escape_json_string(invalid_utf8);
    assert(escaped != NULL);
    assert(strcmp(escaped, "\"x\\u00ff\"") == 0);
    free(escaped);
}

static void test_command_fidelity(void) {
    char *const argv[] = {"spoofed", "two words", "a'b", "", "$HOME", NULL};
    char *command = build_exec_command("/bin/rm", argv);
    assert(command != NULL);
    assert(strcmp(command, "/bin/rm 'two words' 'a'\\''b' '' '$HOME'") == 0);
    free(command);

    char *const normal_argv[] = {"git", "status", NULL};
    command = build_exec_command("/usr/bin/git", normal_argv);
    assert(command != NULL);
    assert(strcmp(command, "git status") == 0);
    free(command);

    char *const no_args[] = {NULL};
    command = build_exec_command("/usr/bin/id", no_args);
    assert(command != NULL);
    assert(strcmp(command, "/usr/bin/id") == 0);
    free(command);
}

static void expect_allowed(const char *json, int expected) {
    int allowed = !expected;
    assert(parse_allowed_response(json, strlen(json), &allowed) == 1);
    assert(allowed == expected);
}

static void expect_invalid(const char *json) {
    int allowed = 1;
    assert(parse_allowed_response(json, strlen(json), &allowed) == 0);
}

static void test_response_parser(void) {
    expect_allowed("{\"allowed\":true}", 1);
    expect_allowed(" { \"message\": \"ok\", \"nested\": [1, {\"x\": false}], \"allowed\": false } ", 0);
    expect_invalid("{\"message\":\"\\\"allowed\\\":true\",\"allowed\":false,}");
    expect_invalid("{\"message\":\"\\\"allowed\\\":true\"}");
    expect_invalid("{\"allowed\":true,\"allowed\":false}");
    expect_invalid("{\"allowed\":\"true\"}");
    expect_invalid("{\"allowed\":true} trailing");
}

static void test_response_bound(void) {
    struct http_response response = {0};
    char byte = 'x';
    assert(write_callback(&byte, 1, MAX_HTTP_RESPONSE_BYTES + 1, &response) == 0);
    assert(response.too_large == 1);
    assert(response.data == NULL);

    response.too_large = 0;
    assert(write_callback(&byte, SIZE_MAX, 2, &response) == 0);
    assert(response.too_large == 1);
}

static void test_endpoint_and_failure_classification(void) {
    assert(safe_http_endpoint("http://127.0.0.1:9090"));
    assert(safe_http_endpoint("HTTPS://example.com/rampart"));
    assert(safe_http_endpoint("http://[::1]:9090"));
    assert(!safe_http_endpoint("file:///tmp/rampart"));
    assert(!safe_http_endpoint("http:///missing-host"));
    assert(!safe_http_endpoint("http://:9090/missing-host"));
    assert(!safe_http_endpoint("http://localhost:/missing-port"));
    assert(!safe_http_endpoint("http://localhost:90:90/ambiguous-port"));
    assert(!safe_http_endpoint("http://user:secret@localhost:9090"));
    assert(!safe_http_endpoint("http://localhost:9090?redirect=https://example.com"));
    assert(!safe_http_endpoint("http://localhost:9090/#fragment"));
    assert(!safe_http_endpoint("http://localhost:9090/line\nbreak"));

    config.mode = "enforce";
    config.fail_open = 1;
    assert(recoverable_failure_result() == 1);
    assert(safety_failure_result() == 0);
    config.mode = "monitor";
    assert(safety_failure_result() == 1);
}

static const char *find_env_value(char *const env[], const char *name) {
    size_t name_len = strlen(name);
    for (size_t i = 0; env && env[i]; i++) {
        if (strncmp(env[i], name, name_len) == 0 && env[i][name_len] == '=') {
            return env[i] + name_len + 1;
        }
    }
    return NULL;
}

static size_t count_env_name(char *const env[], const char *name) {
    size_t count = 0, name_len = strlen(name);
    for (size_t i = 0; env && env[i]; i++) {
        if (strncmp(env[i], name, name_len) == 0 && env[i][name_len] == '=') count++;
    }
    return count;
}

static void test_preload_cascade_environment(void) {
    snprintf(preload_lib_path, sizeof(preload_lib_path), "/tmp/librampart-test");
    free(trusted_preload_value);
    trusted_preload_value = strdup("/tmp/initial:/tmp/librampart-test");
    assert(trusted_preload_value != NULL);
    config_initialization_failed = 0;
    config.url = "http://127.0.0.1:19090";
    config.token = "trusted-token";
    config.mode = "enforce";
    config.fail_open = 0;
    config.debug = 0;
    config.agent = "preload-test";
    config.session = "trusted-session";

    char hostile_preload[256];
    snprintf(hostile_preload, sizeof(hostile_preload), "%s=/tmp/hostile", PRELOAD_ENV_NAME);
    char *env[] = {
        "A=B",
        hostile_preload,
        "RAMPART_URL=http://attacker.invalid",
        "RAMPART_TOKEN=attacker-token",
        "RAMPART_MODE=disabled",
        "RAMPART_FAIL_OPEN=1",
        "RAMPART_DEBUG=1",
        "RAMPART_AGENT=spoofed",
        "RAMPART_SESSION=spoofed",
#ifdef __APPLE__
        "DYLD_FORCE_FLAT_NAMESPACE=0",
#endif
        NULL,
    };
    int modified = 0, failed = 0;
    char **result = build_trusted_child_env(env, &modified, &failed);
    assert(failed == 0);
    assert(modified == 1);
    assert(strcmp(find_env_value(result, "A"), "B") == 0);
    assert(strcmp(find_env_value(result, PRELOAD_ENV_NAME),
                  "/tmp/initial:/tmp/librampart-test") == 0);
    assert(strcmp(find_env_value(result, "RAMPART_URL"), "http://127.0.0.1:19090") == 0);
    assert(strcmp(find_env_value(result, "RAMPART_TOKEN"), "trusted-token") == 0);
    assert(strcmp(find_env_value(result, "RAMPART_MODE"), "enforce") == 0);
    assert(strcmp(find_env_value(result, "RAMPART_FAIL_OPEN"), "0") == 0);
    assert(strcmp(find_env_value(result, "RAMPART_DEBUG"), "0") == 0);
    assert(strcmp(find_env_value(result, "RAMPART_AGENT"), "preload-test") == 0);
    assert(strcmp(find_env_value(result, "RAMPART_SESSION"), "trusted-session") == 0);
#ifdef __APPLE__
    assert(strcmp(find_env_value(result, PRELOAD_AUX_ENV_NAME), "1") == 0);
#endif
    assert(count_env_name(result, PRELOAD_ENV_NAME) == 1);
    assert(count_env_name(result, "RAMPART_MODE") == 1);
    free_modified_envp(result);

    config.token = NULL;
    result = build_trusted_child_env(env, &modified, &failed);
    assert(result != env);
    assert(modified == 1);
    assert(failed == 0);
    assert(find_env_value(result, "RAMPART_TOKEN") == NULL);
    free_modified_envp(result);

    result = build_trusted_child_env(NULL, &modified, &failed);
    assert(result != NULL);
    assert(modified == 1);
    assert(failed == 0);
    assert(strcmp(find_env_value(result, PRELOAD_ENV_NAME),
                  "/tmp/initial:/tmp/librampart-test") == 0);
    assert(find_env_value(result, "RAMPART_TOKEN") == NULL);
    free_modified_envp(result);
}

static volatile int fork_test_mutex_held = 0;

static void *hold_curl_mutex_for_fork(void *unused) {
    (void)unused;
    pthread_mutex_lock(&curl_mutex);
    __sync_lock_test_and_set(&fork_test_mutex_held, 1);
    usleep(100000);
    pthread_mutex_unlock(&curl_mutex);
    return NULL;
}

static void test_multithreaded_fork_does_not_inherit_locked_curl(void) {
    config.url = "http://127.0.0.1:1";
    config.mode = "enforce";
    config.fail_open = 1;

    pthread_t holder;
    fork_test_mutex_held = 0;
    assert(pthread_create(&holder, NULL, hold_curl_mutex_for_fork, NULL) == 0);
    while (!fork_test_mutex_held) usleep(1000);

    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        alarm(5);
        _exit(check_policy("printf fork-safe") ? 0 : 2);
    }

    assert(pthread_join(holder, NULL) == 0);
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0);
}

int main(void) {
    assert(curl_handle != NULL);
    test_json_escaping();
    test_command_fidelity();
    test_response_parser();
    test_response_bound();
    test_endpoint_and_failure_classification();
    test_preload_cascade_environment();
    test_multithreaded_fork_does_not_inherit_locked_curl();
    puts("librampart unit tests passed");
    return 0;
}
