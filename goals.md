# Goals:
## If you aren't running linux (ideally Ubuntu), create a Docker container and proceed inside it
docker run -ti ubuntu:latest /bin/sh
## Compile and run the application
- compile and run the application, typing in to stdin to cause it to read a file on disk
<details>
    <summary>Solution</summary>

    ```sh
    ./compile.sh
    ./target_application
    ```
</details>

## Brief static analysis using IDA
- open the binary in IDA
- find the shared library and interesting function
## Fuzz the shared library given source code
- write a harness and compile it
- download and build LibAFL
- recompile the shared library with 
- run forkserver_simple on the harness
## Brief dynamic analysis using Frida
- run the target application with Frida
    - `pip3 install frida`
    - `frida ./target_application`
- use Frida to capture code coverage, convert the coverage log into an IDC script, and then load it in to IDA
- hook the target application midway through execution to capture code coverage related to parsing the file without capturing code coverage of other interactions with the target appliction
## Circumvent the license check
- find the license check code
    - run the target application with the license flag and then diff the code coverage
        - `./target_application -l`
        - `diff ./coverage.log ./coverage_with_license.log`
- intercept the lisence check call
- write and run a Frida .js script
## Fuzz the binary target application
- simple LibAFL fuzzing... but with Frida!




Unfortunately, you can't `gdb ./target_application` and `frida target_application` at the same time (I think) because linux ptrace doesn't support multiple tracers.
    https://stackoverflow.com/questions/52609394/can-two-process-attach-to-same-pid-via-ptrace
    this says frida uses ptrace
        https://frida.re/docs/installation/
