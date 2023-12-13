Interceptor.attach(Module.getExportByName(null, "open"), {
    onEnter(args) {
        const path = args[0].readUtf8String();
        log(`open() path="${path}"`);
    }
});
