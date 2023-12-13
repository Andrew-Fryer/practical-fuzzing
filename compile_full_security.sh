./custom_compile.sh -o target_application_full_security -s 12

# This isn't really necessary, but does reduce the size of the binary
strip -s target_build/target_application_full_security
