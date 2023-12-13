#!/bin/bash

# Default values
output_file=""
selected_options=""

export C_INCLUDE_PATH=target_src

gcc -Wall -g -c target_src/target_application.c -o target_build/target_application.o
gcc -Wall -g -c target_src/target_library.c -o target_build/target_library.o

# Parse command line arguments
if [ $# -eq 0 ]; then

    echo "CLI flags are as follow"
    echo " -o [filename]: Specify Output file."
    echo " -s [{1-10},{1-10},{1-10}]: Specify security features. (11=None, 12=All.) \n"
    read -p "Enter the desired name for the compiled file (without extension): " output_file

    echo "Please select the wanted options for the compilation of your file:"
    echo "1) Stripped file"
    echo "2) Relro (Partial RELocation Read-Only)"
    echo "3) No-Relro"
    echo "4) Canary"
    echo "5) No-Canary"
    echo "6) PIE (Position Independent Executable)"
    echo "7) No-PIE"
    echo "8) NX (No eXecute)"
    echo "9) No-NX"
    echo "10) Default (No specific security features)"
    echo "11) Disable all security features"
    echo "12) Enable all security features and Stripped file"
    read -p "Enter the numbers of your choices (e.g., 1,3,5): " selected_options

    IFS=',' read -ra selected_options <<< "$selected_options"
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            output_file="$2"
            shift 2
            ;;
        -s|--security)
            selected_options="$2"
            IFS=',' read -ra selected_options <<< "$selected_options"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check if output file name is provided
if [ -z "$output_file" ]; then
    echo "Output file name is required."
    exit 1
fi

# Check if security options are provided
if [ -z "$selected_options" ]; then
    echo "Security options are required."
    exit 1
fi

# Insert the provided code block here
compile_command="gcc -Wall -g -o target_build/$output_file"

contains_option_1=false

for option in "${selected_options[@]}"; do
    # Check if option 1 is selected
    if [[ $option -eq 1 ]]; then
        contains_option_1=true
    fi

    case $option in
        1)
            gcc -Wall -c target_src/target_application.c -o target_build/target_application.o
            gcc -Wall -c target_src/target_library.c -o target_build/target_library.o
            compile_command+=" -s"
            ;;
        2)
            compile_command+=" -z relro -z now"
            ;;
	    3)
            compile_command+=" -z norelro"
            ;;
        4)
            # Check if option 1 is selected to maintain the -g flag status
            if $contains_option_1; then
                # Use specific compilation commands without -g flag for smaller size
                gcc -Wall -fstack-protector-all -c target_src/target_application.c -o target_build/target_application.o
                gcc -Wall -fstack-protector-all -c target_src/target_library.c -o target_build/target_library.o
            else
                # Use specific compilation commands with -g flag for debugging symbols
                gcc -Wall -g -fstack-protector-all -c target_src/target_application.c -o target_build/target_application.o
                gcc -Wall -g -fstack-protector-all -c target_src/target_library.c -o target_build/target_library.o
            fi
            ;;
        5)
            compile_command+=" -fno-stack-protector"
            ;;
        6)
            compile_command+=" -pie -fpie"
            ;;
        7)
            compile_command+=" -no-pie"
            ;;
        8)
            compile_command+=" -z noexecstack"
            ;;
        9)
            compile_command+=" -z execstack"
            ;;
        10)
            echo "Using default compilation options."
            ;;
        11)
            compile_command="gcc -Wall -z norelro -z execstack -g -o target_build/$output_file target_build/target_application.o target_build/target_library.o -fno-stack-protector -no-pie"
            ;;
        12)
            gcc -Wall -fstack-protector-all -c target_src/target_application.c -o target_build/target_application.o
            gcc -Wall -fstack-protector-all -c target_src/target_library.c -o target_build/target_library.o
            compile_command="gcc -Wall -o target_build/$output_file -s -z relro -z now target_build/target_application.o target_build/target_library.o -pie -fpie -z noexecstack"
            ;;
        *)
            echo "Invalid option: $option. Skipping..."
            ;;
    esac
done

if ! [[ " ${selected_options[@]} " =~ " 11 " ]] && ! [[ " ${selected_options[@]} " =~ " 12 " ]] ; then
    compile_command+=" target_build/target_application.o target_build/target_library.o"
fi

echo "Executing the following compilation command:"
echo "$compile_command"
eval "$compile_command"

echo "Compilation completed successfully!"
