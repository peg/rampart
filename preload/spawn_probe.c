/*
 * Copyright 2026 The Rampart Authors
 * Licensed under the Apache License, Version 2.0
 */

#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>

extern char **environ;

int main(int argc, char **argv) {
    int use_path_search = argc > 1 && strcmp(argv[1], "spawnp") == 0;
    char *child_argv[] = {"spoofed-argv-zero", NULL};
    pid_t pid = 0;
    int result;
    if (use_path_search) {
        result = posix_spawnp(&pid, "true", NULL, NULL, child_argv, environ);
    } else {
        result = posix_spawn(&pid, "/bin/true", NULL, NULL, child_argv, environ);
    }
    if (result != 0) {
        fprintf(stderr, "spawn failed: %d\n", result);
        return 1;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return 2;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 3;
}
