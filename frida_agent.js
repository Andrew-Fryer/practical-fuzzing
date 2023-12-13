console.log(`PID: ${Process.id}`);

new ModuleMap().values().forEach(m => {
    console.log(`${m.base}-${m.base.add(m.size)} ${m.name}`);
});
console.log("Hello,\nI'm running in the target process");

const cm = new CModule(`
#include <stdio.h>

void hello(void) {
  printf("Hello,\\nI'm c code in the target process\\n");
}
`);
const hello_fn = new NativeFunction(cm.hello, 'void', []);
hello_fn();
