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

static void test_preload_cascade_environment(void) {
    snprintf(preload_lib_path, sizeof(preload_lib_path), "/tmp/librampart-test");
    char existing[256];
    snprintf(existing, sizeof(existing), "%s=/tmp/other", PRELOAD_ENV_NAME);
    char *env[] = {"A=B", existing, NULL};
    int modified = 0, failed = 0;
    char **result = ensure_preload_env(env, &modified, &failed);
    assert(failed == 0);
    assert(modified == 1);
    char expected[256];
    snprintf(expected, sizeof(expected), "%s=/tmp/other:/tmp/librampart-test", PRELOAD_ENV_NAME);
    assert(strcmp(result[1], expected) == 0);
    free_modified_envp(result);

    snprintf(existing, sizeof(existing), "%s=/tmp/librampart-test", PRELOAD_ENV_NAME);
    result = ensure_preload_env(env, &modified, &failed);
    assert(result == env);
    assert(modified == 0);
    assert(failed == 0);

    result = ensure_preload_env(NULL, &modified, &failed);
    assert(result != NULL);
    assert(modified == 1);
    assert(failed == 0);
    snprintf(expected, sizeof(expected), "%s=/tmp/librampart-test", PRELOAD_ENV_NAME);
    assert(strcmp(result[0], expected) == 0);
    assert(result[1] == NULL);
    free_modified_envp(result);
}

int main(void) {
    assert(curl_handle != NULL);
    test_json_escaping();
    test_command_fidelity();
    test_response_parser();
    test_response_bound();
    test_preload_cascade_environment();
    puts("librampart unit tests passed");
    return 0;
}
