const dummy_api = {
    print: console.log,
    setInMemoryFuzzing: () => {},
    setPersistentAddress: () => {},
    done: () => {},
};
// const Afl = dummy_api; // un-comment if using this script without AFLplusplus
console.log = Afl.print;


// TODO: put your code to circumvent the license check here
//
//

const dummy_file_path = "dummy_input_file.txt";

const before_entering_1 = 'before entering 1';
const before_entering_file_path = 'before entering file path';
const before_opening_file = 'before opening file';
const before_reading_file = 'before reading file';
const before_entering_2 = 'before entering 2';
const done = 'done';

const initial_state = before_entering_1;
const after_entering_1 = before_entering_file_path;
const after_entering_file_path = before_opening_file;
const after_opening_file = before_reading_file;
const after_reading_file = before_entering_2;

let app_state = initial_state;

const fopen_fn_addr = Module.findExportByName(null, 'fopen');
Interceptor.attach(ptr(fopen_fn_addr), {
    onEnter(args) {
        this.is_dummy_file = false;
        if(app_state === before_opening_file) {
            console.log('considering ' + args[0].readUtf8String() + ' and in state ' + app_state);
            this.is_dummy_file = args[0].readUtf8String().includes(dummy_file_path);
        }
    },
    onLeave(retval) {
        if(this.is_dummy_file) {
            app_state = after_opening_file;
        }
    },
});

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
            return i;
        } else if(app_state === before_entering_2) {
            console.log('writing \'2\'');
            buf.add(0).writeU8(0x32); // '2'
            buf.add(1).writeU8(0x0A); // NL
            app_state = done;
            return 2;
        } else {
            console.log('WAT WAT WAT: This should never happen');
        }
    } else {
        // this must be AFL using the read fn
        // So, call the actual read fn
        console.log('Calling through to real read fn');
        return read_fn(fd, buf, size);
    }
}, 'int', ['int', 'pointer', 'int']));

const fread_fn_addr = Module.findExportByName(null, 'fread');
console.log('fread_fn_addr: ' + fread_fn_addr);
const fread_fn = new NativeFunction(fread_fn_addr, 'int', ['pointer', 'int', 'int', 'pointer']);
Interceptor.replace(ptr(fread_fn_addr), new NativeCallback((buf, size, nitems, file) => {
    if(app_state === before_reading_file) {
        // we must be reading in the file data that will be parsed
        const afl_fuzz_len_ptr = Afl.getAflFuzzLen().readPointer();
        const afl_fuzz_len = afl_fuzz_len_ptr.readU32();
        const afl_fuzz_ptr = Afl.getAflFuzzPtr().readPointer();
        const data = afl_fuzz_ptr.readByteArray(afl_fuzz_len);
        console.log('writing data: ' + new Uint8Array(data) + ' (' + afl_fuzz_len + ' bytes)');
        buf.writeByteArray(data);
        app_state = after_reading_file;
        return afl_fuzz_len;
    } else {
        console.log("calling through to fread");
        return fread_fn(buf, size, nitems, file);
    }
}, 'int', ['pointer', 'int', 'int', 'pointer']));

Afl.setInMemoryFuzzing();

console.log('at end of script');
Afl.done();
