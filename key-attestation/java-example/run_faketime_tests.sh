#!/bin/bash

# Check if faketime is installed
if ! command -v faketime &> /dev/null; then
    echo "faketime is not installed. Please install it using 'sudo apt install faketime'."
    exit 1
fi

# Tell tests that faketime is active
export FAKE_TIME_ACTIVE=1

# Run Maven tests with faketime active
faketime --exclude-monotonic '2023-09-15 10:00:00' mvn test -Dstyle.color=always -Dtest=VerifyTest