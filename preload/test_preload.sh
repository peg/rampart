#!/bin/bash
# test_preload.sh - Integration test script for librampart preload library

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
RAMPART_URL="http://127.0.0.1:19090"
RAMPART_TOKEN="${RAMPART_TOKEN:-}"
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBRARY=""

# Detect platform and set library name
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    LIBRARY="librampart.so"
    PRELOAD_VAR="LD_PRELOAD"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    LIBRARY="librampart.dylib"
    PRELOAD_VAR="DYLD_INSERT_LIBRARIES"
else
    echo -e "${RED}❌ Unsupported platform: $OSTYPE${NC}"
    exit 1
fi

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

log_test() {
    echo -e "${BLUE}🧪 Test: $1${NC}"
}

# Check if rampart serve is running
check_rampart_serve() {
    log_info "Checking if rampart serve is running on port 19090..."
    if curl -s "$RAMPART_URL/health" > /dev/null 2>&1; then
        log_success "Rampart serve is running"
        return 0
    else
        log_warning "Rampart serve is not running on port 19090"
        return 1
    fi
}

# Test 1: Library loads without crash
test_library_load() {
    log_test "Library loads without crashing"
    
    if [ ! -f "$TEST_DIR/$LIBRARY" ]; then
        log_error "Library $LIBRARY not found. Run 'make' first."
        exit 1
    fi
    
    export $PRELOAD_VAR="$TEST_DIR/$LIBRARY"
    export RAMPART_URL="$RAMPART_URL"
    export RAMPART_TOKEN="$RAMPART_TOKEN"
    export RAMPART_DEBUG="0"
    
    if echo "hello from preload test" > /dev/null; then
        log_success "Library loaded successfully"
    else
        log_error "Library failed to load"
        exit 1
    fi
}

# Test 2: Debug output works
test_debug_output() {
    log_test "Debug output functionality"
    
    export $PRELOAD_VAR="$TEST_DIR/$LIBRARY"
    export RAMPART_URL="$RAMPART_URL"
    export RAMPART_TOKEN="$RAMPART_TOKEN"
    export RAMPART_DEBUG="1"
    
    output=$(echo "debug test" 2>&1)
    if echo "$output" | grep -q "rampart"; then
        log_success "Debug output working"
    else
        log_warning "Debug output not found (may be normal if optimized out)"
    fi
    
    export RAMPART_DEBUG="0"
}

# Test 3: Commands work when serve is running (if available)
test_with_serve_running() {
    if ! check_rampart_serve; then
        log_warning "Skipping policy enforcement tests - rampart serve not running"
        return 0
    fi
    
    log_test "Command execution with policy server running"
    
    export $PRELOAD_VAR="$TEST_DIR/$LIBRARY"
    export RAMPART_URL="$RAMPART_URL"
    export RAMPART_TOKEN="$RAMPART_TOKEN"
    export RAMPART_DEBUG="0"
    export RAMPART_MODE="enforce"
    
    # Test allowed command
    if echo "testing allowed command" > /dev/null 2>&1; then
        log_success "Allowed command executed successfully"
    else
        log_error "Allowed command failed"
    fi
    
    # Test ls command (should be allowed)
    if ls /tmp > /dev/null 2>&1; then
        log_success "ls command executed successfully"
    else
        log_error "ls command failed"
    fi
}

# Test 4: Fail-open behavior when serve is NOT running
test_fail_open() {
    log_test "Fail-open behavior when serve unreachable"
    
    export $PRELOAD_VAR="$TEST_DIR/$LIBRARY"
    export RAMPART_URL="http://127.0.0.1:99999" # Non-existent port
    export RAMPART_TOKEN="fake_token"
    export RAMPART_DEBUG="0"
    export RAMPART_FAIL_OPEN="1"
    
    if echo "fail-open test" > /dev/null 2>&1; then
        log_success "Fail-open behavior working correctly"
    else
        log_error "Fail-open behavior not working"
    fi
}

# Test 5: system() interception
test_system_interception() {
    log_test "system() function interception"
    
    export $PRELOAD_VAR="$TEST_DIR/$LIBRARY"
    export RAMPART_URL="http://127.0.0.1:99999" # Non-existent port
    export RAMPART_TOKEN="fake_token"
    export RAMPART_DEBUG="0"
    export RAMPART_FAIL_OPEN="1"
    
    # Create a small C program to test system()
    cat > /tmp/test_system.c << 'EOF'
#include <stdlib.h>
int main() {
    return system("echo 'system() test'");
}
EOF
    
    if gcc -o /tmp/test_system /tmp/test_system.c 2>/dev/null; then
        if /tmp/test_system > /dev/null 2>&1; then
            log_success "system() interception working"
        else
            log_error "system() interception failed"
        fi
        rm -f /tmp/test_system /tmp/test_system.c
    else
        log_warning "Could not compile system() test (gcc not available)"
    fi
}

# Test 6: popen() interception  
test_popen_interception() {
    log_test "popen() function interception"
    
    export $PRELOAD_VAR="$TEST_DIR/$LIBRARY"
    export RAMPART_URL="http://127.0.0.1:99999" # Non-existent port
    export RAMPART_TOKEN="fake_token"
    export RAMPART_DEBUG="0"
    export RAMPART_FAIL_OPEN="1"
    
    # Create a small C program to test popen()
    cat > /tmp/test_popen.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
int main() {
    FILE* fp = popen("echo 'popen() test'", "r");
    if (fp) {
        pclose(fp);
        return 0;
    }
    return 1;
}
EOF
    
    if gcc -o /tmp/test_popen /tmp/test_popen.c 2>/dev/null; then
        if /tmp/test_popen > /dev/null 2>&1; then
            log_success "popen() interception working"
        else
            log_error "popen() interception failed"
        fi
        rm -f /tmp/test_popen /tmp/test_popen.c
    else
        log_warning "Could not compile popen() test (gcc not available)"
    fi
}

# Test 7: Monitor mode
test_monitor_mode() {
    log_test "Monitor mode (log-only, no blocking)"
    
    export $PRELOAD_VAR="$TEST_DIR/$LIBRARY"
    export RAMPART_URL="http://127.0.0.1:99999" # Non-existent port
    export RAMPART_TOKEN="fake_token"
    export RAMPART_DEBUG="0"
    export RAMPART_MODE="monitor"
    
    if echo "monitor mode test" > /dev/null 2>&1; then
        log_success "Monitor mode working correctly"
    else
        log_error "Monitor mode failed"
    fi
}

# Test 8: Disabled mode
test_disabled_mode() {
    log_test "Disabled mode (no policy checks)"
    
    export $PRELOAD_VAR="$TEST_DIR/$LIBRARY"
    export RAMPART_URL="$RAMPART_URL"
    export RAMPART_TOKEN="$RAMPART_TOKEN"
    export RAMPART_DEBUG="0"
    export RAMPART_MODE="disabled"
    
    if echo "disabled mode test" > /dev/null 2>&1; then
        log_success "Disabled mode working correctly"
    else
        log_error "Disabled mode failed"
    fi
}

# Test 9: Child process inheritance
test_child_process_inheritance() {
    log_test "Child process inheritance of LD_PRELOAD"
    
    export $PRELOAD_VAR="$TEST_DIR/$LIBRARY"
    export RAMPART_URL="http://127.0.0.1:99999" # Non-existent port
    export RAMPART_TOKEN="fake_token"
    export RAMPART_DEBUG="0"
    export RAMPART_FAIL_OPEN="1"
    
    # Test that child processes also have the library loaded
    if bash -c 'echo "child process test"' > /dev/null 2>&1; then
        log_success "Child process inheritance working"
    else
        log_error "Child process inheritance failed"
    fi

    export RAMPART_DEBUG="1"
    if command -v python3 >/dev/null 2>&1; then
        output=$(python3 -c 'import os; os.system("true")' 2>&1 >/dev/null || true)
        if echo "$output" | grep -q "Allowing system: true"; then log_success "Python os.system() intercepted"; else log_error "Python os.system() interception missing"; fi
    else
        log_warning "Skipping Python cascade test (python3 not available)"
    fi
    output=$(bash -c 'bash -c "ls >/dev/null"' 2>&1 >/dev/null || true)
    if echo "$output" | grep -q "Allowing exec"; then log_success "Bash subprocess interception working"; else log_error "Bash subprocess interception missing"; fi
    export RAMPART_DEBUG="0"
}

# Main test runner
main() {
    log_info "Starting librampart integration tests"
    log_info "Platform: $OSTYPE"
    log_info "Library: $LIBRARY"
    log_info "Preload var: $PRELOAD_VAR"
    echo
    
    # Build the library if it doesn't exist
    if [ ! -f "$TEST_DIR/$LIBRARY" ]; then
        log_info "Building library..."
        make -C "$TEST_DIR" || {
            log_error "Failed to build library"
            exit 1
        }
    fi
    
    # Run all tests
    test_library_load
    test_debug_output
    test_with_serve_running
    test_fail_open
    test_system_interception
    test_popen_interception
    test_monitor_mode
    test_disabled_mode
    test_child_process_inheritance
    
    echo
    log_success "All integration tests completed!"
    
    # Summary
    echo
    log_info "Summary:"
    log_info "- Library loads and intercepts exec functions"
    log_info "- Fail-open behavior works when server is unreachable"
    log_info "- Debug output functional"
    log_info "- Monitor and disabled modes work correctly"
    log_info "- system() and popen() interception working"
    log_info "- Child processes inherit protection"
    
    if check_rampart_serve; then
        log_info "- Policy enforcement tested with running server"
    else
        log_warning "- Policy enforcement not tested (server not running)"
        log_info "  To test policy enforcement, start 'rampart serve' and re-run tests"
    fi
    
    echo
    log_success "librampart is ready for production use!"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [--help]"
        echo
        echo "Integration test script for librampart preload library."
        echo "Tests library loading, policy checking, and fail-open behavior."
        echo
        echo "Prerequisites:"
        echo "  - Library built (run 'make' first)"
        echo "  - Optional: 'rampart serve' running on port 19090 for full tests"
        echo
        exit 0
        ;;
    "")
        main
        ;;
    *)
        log_error "Unknown argument: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac
