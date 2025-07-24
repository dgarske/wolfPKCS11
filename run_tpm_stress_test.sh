#!/bin/bash

# run_tpm_stress_test.sh - TPM Memory Stress Test Runner
#
# This script runs the TPM memory test multiple times to stress test
# TPM memory consumption and detect potential memory leaks or exhaustion.

set -e

# Default values
ITERATIONS=5
DELAY=2
VERBOSE=0
LIB_PATH=""
USER_PIN=""
SLOT=""
NO_CLEANUP=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

usage() {
    echo "TPM Memory Stress Test Runner"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -i, --iterations <num>    Number of test iterations (default: 5)"
    echo "  -d, --delay <seconds>     Delay between iterations (default: 2)"
    echo "  -v, --verbose             Enable verbose output"
    echo "  -l, --lib <path>          PKCS#11 library path"
    echo "  -p, --pin <pin>           User PIN"
    echo "  -s, --slot <num>          Slot number"
    echo "  -n, --no-cleanup          Skip cleanup between iterations"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                        # Run 5 iterations with default settings"
    echo "  $0 -i 10 -d 5            # Run 10 iterations with 5 second delay"
    echo "  $0 -v -i 3               # Run 3 iterations with verbose output"
    echo "  $0 -n -i 20              # Run 20 iterations without cleanup (stress test)"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--iterations)
            ITERATIONS="$2"
            shift 2
            ;;
        -d|--delay)
            DELAY="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -l|--lib)
            LIB_PATH="$2"
            shift 2
            ;;
        -p|--pin)
            USER_PIN="$2"
            shift 2
            ;;
        -s|--slot)
            SLOT="$2"
            shift 2
            ;;
        -n|--no-cleanup)
            NO_CLEANUP=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Validate iterations
if ! [[ "$ITERATIONS" =~ ^[0-9]+$ ]] || [ "$ITERATIONS" -lt 1 ]; then
    log_error "Invalid number of iterations: $ITERATIONS"
    exit 1
fi

# Validate delay
if ! [[ "$DELAY" =~ ^[0-9]+$ ]] || [ "$DELAY" -lt 0 ]; then
    log_error "Invalid delay: $DELAY"
    exit 1
fi

# Check if test binary exists
TEST_BINARY="./tests/tpm_memory_test"
if [ ! -f "$TEST_BINARY" ]; then
    log_error "Test binary not found: $TEST_BINARY"
    log_info "Please build the test first: make tests/tpm_memory_test"
    exit 1
fi

# Build command line arguments for test
TEST_ARGS=""
if [ "$VERBOSE" -eq 1 ]; then
    TEST_ARGS="$TEST_ARGS -v"
fi
if [ -n "$LIB_PATH" ]; then
    TEST_ARGS="$TEST_ARGS -lib $LIB_PATH"
fi
if [ -n "$USER_PIN" ]; then
    TEST_ARGS="$TEST_ARGS -userPin $USER_PIN"
fi
if [ -n "$SLOT" ]; then
    TEST_ARGS="$TEST_ARGS -slot $SLOT"
fi

# Statistics tracking
SUCCESS_COUNT=0
FAILURE_COUNT=0
START_TIME=$(date +%s)

log_info "Starting TPM Memory Stress Test"
log_info "Iterations: $ITERATIONS"
log_info "Delay between iterations: ${DELAY}s"
log_info "No cleanup: $([ $NO_CLEANUP -eq 1 ] && echo "Yes" || echo "No")"
log_info "Test command: $TEST_BINARY $TEST_ARGS"
echo ""

# Create log directory
LOG_DIR="tpm_stress_logs_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"
log_info "Logs will be saved to: $LOG_DIR"

# Run iterations
for ((i=1; i<=ITERATIONS; i++)); do
    echo -e "${BLUE}=== Iteration $i of $ITERATIONS ===${NC}"

    # Create individual log file for this iteration
    ITERATION_LOG="$LOG_DIR/iteration_${i}.log"

    # Run the test
    if [ "$VERBOSE" -eq 1 ]; then
        echo "Running: $TEST_BINARY $TEST_ARGS"
    fi

    if $TEST_BINARY $TEST_ARGS > "$ITERATION_LOG" 2>&1; then
        log_success "Iteration $i completed successfully"
        ((SUCCESS_COUNT++))

        # Show summary from log if not verbose
        if [ "$VERBOSE" -eq 0 ]; then
            grep -E "(Successfully created|SUCCESS:|Created [0-9]+ objects)" "$ITERATION_LOG" | head -1
        else
            cat "$ITERATION_LOG"
        fi
    else
        EXIT_CODE=$?
        log_error "Iteration $i failed with exit code: $EXIT_CODE"
        ((FAILURE_COUNT++))

        # Show error details
        echo "Error details:"
        tail -10 "$ITERATION_LOG"

        # If this is a memory-related failure, we might want to stop
        if grep -q -E "(DEVICE_MEMORY|DEVICE_ERROR|out of memory)" "$ITERATION_LOG"; then
            log_warning "Memory-related error detected. This might indicate TPM memory exhaustion."
        fi
    fi

    # Memory usage information (if available)
    if command -v free >/dev/null 2>&1; then
        echo "System memory: $(free -h | grep '^Mem:' | awk '{print $3 "/" $2}')"
    fi

    # Wait before next iteration (except for the last one)
    if [ $i -lt $ITERATIONS ] && [ $DELAY -gt 0 ]; then
        log_info "Waiting ${DELAY}s before next iteration..."
        sleep $DELAY
    fi

    echo ""
done

# Final statistics
END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))

echo -e "${BLUE}=== Test Summary ===${NC}"
log_info "Total iterations: $ITERATIONS"
log_success "Successful: $SUCCESS_COUNT"
if [ $FAILURE_COUNT -gt 0 ]; then
    log_error "Failed: $FAILURE_COUNT"
else
    log_success "Failed: $FAILURE_COUNT"
fi
log_info "Total time: ${TOTAL_TIME}s"
log_info "Success rate: $(( SUCCESS_COUNT * 100 / ITERATIONS ))%"

# Check for patterns in failures
if [ $FAILURE_COUNT -gt 0 ]; then
    echo ""
    log_info "Analyzing failure patterns..."

    # Look for common error patterns across all logs
    if grep -l -E "(DEVICE_MEMORY|out of memory)" "$LOG_DIR"/*.log >/dev/null 2>&1; then
        log_warning "Memory exhaustion detected in some iterations"
    fi

    if grep -l -E "(DEVICE_ERROR|TPM_RC)" "$LOG_DIR"/*.log >/dev/null 2>&1; then
        log_warning "TPM device errors detected in some iterations"
    fi
fi

# Cleanup suggestion
if [ $NO_CLEANUP -eq 1 ] && [ $SUCCESS_COUNT -gt 0 ]; then
    echo ""
    log_warning "Objects from successful iterations may still be stored in TPM"
    log_info "Consider running cleanup or resetting the token if TPM memory is exhausted"
fi

echo ""
log_info "Detailed logs available in: $LOG_DIR"

# Exit with appropriate code
if [ $FAILURE_COUNT -eq 0 ]; then
    log_success "All iterations completed successfully!"
    exit 0
else
    log_error "Some iterations failed. Check logs for details."
    exit 1
fi
