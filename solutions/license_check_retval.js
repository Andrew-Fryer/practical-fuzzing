// Use this file like so: `cd practical_fuzzing; frida -f ./target_build/target_application_full_security -l solutions/license_check_retval.js --stdio=pipe`

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
    license_check_addr = parseInt(application_module.base) + license_check_relative_addr;
}
console.log(license_check_addr);
Interceptor.attach(ptr(license_check_addr), {
    onLeave(retval) {
        retval.replace(0x01);
    },
});

console.log('In a separate terminal, run `cat > /proc/' + Process.id + '/fd/0` to feed the target application text on its stdin');
