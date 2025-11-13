#!/bin/bash

set -euo pipefail

DURATION="60m"
JOBS_PER_TEST=6
TARGET_CLASS="org.tukaani.xz.fuzz.FuzzTests"
COVERAGE_DIR="fuzz/target/coverage-reports"

FUZZ_TESTS=(
    "fuzzRoundTrip"
    "fuzzEncoders"
    "fuzzDecode"
    "fuzzDecompressionBomb"
    "fuzzConcatenatedStreams"
    "fuzzSeekableInputStreams"
    "fuzzDictionarySizes"
    "fuzzXzVsApacheCommons"
    "fuzzBasicArrayCache"
    "fuzzLZMA2Encoder"
)

maven() {
    mvn -f fuzz/pom.xml "$@"
}

maven clean
mkdir -p ${COVERAGE_DIR}

echo "=== Running fuzzing for ${DURATION} ==="

for fuzz_test in "${FUZZ_TESTS[@]}"; do
  echo "Fuzzing: ${fuzz_test}"

  pids=()

  for ((i=1; i <= JOBS_PER_TEST; i++)); do
    (
      JAZZER_FUZZ=1 maven \
        -Djazzer.max_duration=${DURATION} \
        -Dtest="${TARGET_CLASS}#${fuzz_test}" \
        -Dmaven.test.failure.ignore=true \
        test
    ) &
    pids+=($!)
  done

  # Wait for all fuzzing jobs to finish
  for pid in "${pids[@]}"; do
    wait "$pid"
  done
done

echo "=== Replaying corpus for coverage ==="

for fuzz_test in "${FUZZ_TESTS[@]}"; do
  echo "Replaying: ${fuzz_test}"

  maven \
    jacoco:prepare-agent \
    -Dtest="${TARGET_CLASS}#${fuzz_test}" \
    -Dmaven.test.failure.ignore=true \
    test

  if [ -f "target/jacoco.exec" ]; then
    mv target/jacoco.exec "${COVERAGE_DIR}/jacoco-${fuzz_test}.exec"
  else
    echo "No coverage data found"
  fi
done

echo "=== Merging data and creating report ==="

maven jacoco:merge@merge-results jacoco:report
