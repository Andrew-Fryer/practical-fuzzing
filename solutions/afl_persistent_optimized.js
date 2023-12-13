const dummy_api = {
    print: console.log,
    setInMemoryFuzzing: () => {},
    setPersistentAddress: () => {},
    done: () => {},
};
// const Afl = dummy_api; // un-comment if using this script without AFLplusplus
console.log = Afl.print;


const modules = Process.enumerateModules();
const application_module = modules[0];
const symbols = application_module.enumerateSymbols();
let license_check_addr;
const symbols_matching_license_check = symbols.filter(s => s.name === 'license_check');
if(symbols_matching_license_check.length === 1) {
    // this should work if symbols aren't stripped
    license_check_addr = symbols_matching_license_check[0].address;
} else {
    // resort to this if the binary is stripped
    const license_check_relative_addr = 0x00000000000012E9; // copied from IDA (without rebasing the program in IDA, so the segment base is 0x00 in IDA).
    license_check_addr = ptr(parseInt(application_module.base) + license_check_relative_addr);
}
console.log("license_check_addr: " + license_check_addr);
Interceptor.attach(license_check_addr, {
    onLeave(retval) {
        retval.replace(0x01);
    },
});

const dummy_file_path = "dummy_input_file.txt";

const before_entering_1 = 'before entering 1';
const before_entering_file_path = 'before entering file path';
const in_fuzz_loop = 'in fuzz loop';

const initial_state = before_entering_1;
const after_entering_1 = before_entering_file_path;
const after_entering_file_path = in_fuzz_loop;

const c_in_fuzz_loop = Memory.alloc(4);
c_in_fuzz_loop.writeU32(0);
console.log("c_in_fuzz_loop: " + c_in_fuzz_loop + " : " + c_in_fuzz_loop.readInt());

let app_state = initial_state;

const read_fn_addr = Module.findExportByName(null, 'read');
const read_fn = new NativeFunction(read_fn_addr, 'int', ['int', 'pointer', 'int']);
Interceptor.replace(ptr(read_fn_addr), new NativeCallback((fd, buf, size) => {
    if(fd === 0) {
        console.log('reading from stdin');
        if(app_state === before_entering_1) {
            console.log('writing \'1\'');
            buf.add(0).writeU8(0x31); // '1'
            buf.add(1).writeU8(0x0A); // NL
            app_state = after_entering_1;
            return 2;
        } else if(app_state === before_entering_file_path) {
            // Note that `dummy_file_path` is opened, but not actually read from
            console.log('writing <dummy path>: ' + dummy_file_path);
            buf.writeUtf8String(dummy_file_path);
            let i = dummy_file_path.length;
            buf.add(i).writeU8(0x0A); // NL
            i += 1;
            app_state = after_entering_file_path;
            c_in_fuzz_loop.writeU32(1);
            return i;
        } else {
            console.log('WAT WAT WAT: This should never happen');
        }
    } else {
        // this must be AFL using the read fn
        // So, call the actual read fn
        // console.log('Calling through to real read fn'); // commented to reduce logging
        return read_fn(fd, buf, size);
    }
}, 'int', ['int', 'pointer', 'int']));

const fopen_fn_addr = Module.findExportByName(null, 'fopen');
// const fopen_fn = new NativeFunction
console.log('Here ' + fopen_fn_addr);
const fopen_cm = new CModule(`
#include <stdio.h>

extern unsigned int c_in_fuzz_loop;
extern FILE * fopen(char * path, char * mode);

FILE * shim_fopen(char * path, char * mode) {
    // printf("here in shim_fopen %s %d\\n", path, c_in_fuzz_loop);
    if(c_in_fuzz_loop) {
        // do nothing
        return (FILE *) 1; // arbitrary positive pointer
    } else {
        return fopen(path, mode);
    }
}`, {
    c_in_fuzz_loop,
    fopen: fopen_fn_addr,
});
console.log(fopen_cm);
Interceptor.replace(ptr(fopen_fn_addr), fopen_cm.shim_fopen);

const fclose_fn_addr = Module.findExportByName(null, 'fclose');
const fclose_cm = new CModule(`
#include <stdio.h>

extern unsigned int c_in_fuzz_loop;
extern int fclose(FILE * f);

int shim_fclose(FILE * f) {
    // printf("here in shim_fclose %d\\n", c_in_fuzz_loop);
    if(c_in_fuzz_loop) {
        // do nothing
        return 0; // 0 indicates success
    } else {
        return fclose(f);
    }
}`, {
    c_in_fuzz_loop,
    fclose: fclose_fn_addr,
});
Interceptor.replace(ptr(fclose_fn_addr), fclose_cm.shim_fclose);

const fread_fn_addr = Module.findExportByName(null, 'fread');
console.log('fread_fn_addr: ' + fread_fn_addr);
const fread_cm = new CModule(`
#include <stdio.h>
#include <string.h>

extern unsigned char * __afl_fuzz_ptr;
extern unsigned int * __afl_fuzz_len;
extern unsigned int c_in_fuzz_loop;
extern int fread(unsigned char * ptr, int size, int nitems, FILE * stream);

int shim_fread(unsigned char * ptr, int size, int nitems, FILE * stream) {
    // printf("here in shim_fread %d\\n", c_in_fuzz_loop);
    if(c_in_fuzz_loop) {
        int len = *__afl_fuzz_len;
        if(size < len) {
            len = size;
        }
        memcpy(ptr, __afl_fuzz_ptr, len);
        return len;
    } else {
        // call through to real fread fn
        return fread(ptr, size, nitems, stream);
    }
}`, {
    __afl_fuzz_ptr: Afl.getAflFuzzPtr(),
    __afl_fuzz_len: Afl.getAflFuzzLen(),
    c_in_fuzz_loop,
    fread: ptr(fread_fn_addr),
});
Interceptor.replace(ptr(fread_fn_addr), fread_cm.shim_fread);

Afl.setInMemoryFuzzing();

let parse_fn_addr;
const symbols_matching_parse_file = symbols.filter(s => s.name === 'parse_file');
if(symbols_matching_parse_file.length === 1) {
    // this should work if symbols aren't stripped
    parse_fn_addr = symbols_matching_parse_file[0].address;
} else {
    // resort to this if the binary is stripped
    const parse_fn_relative_addr = 0x00000000000017BC; // copied from IDA (without rebasing the program in IDA, so the segment base is 0x00 in IDA).
    parse_fn_addr = ptr(parseInt(application_module.base) + parse_fn_relative_addr);
}
console.log("parse_fn_addr: " + parse_fn_addr);
Afl.setPersistentAddress(parse_fn_addr);

console.log('at end of script');
Afl.done();
