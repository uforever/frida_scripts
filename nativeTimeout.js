const targetLib = "libroysue.so";

function HookNative() {
    console.log("-------- Start Hooking --------");

    // 寻找目标库的基址
    // const baseAddress = Module.findBaseAddress(targetLib);
    // console.log("baseAddress: " + baseAddress);

    // 直接寻找导出函数
    // if (baseAddress) {
    //     const funcAddr = Module.findExportByName(targetLib, '_Z4fuckP7_JNIEnvP7_jclassP8_jstring');
    //     console.log("funcAddr: " + funcAddr);
    //     console.log(`offset: 0x${(funcAddr - baseAddress).toString(16)}`);
    // }

    // 枚举导出
    // const exports = Module.enumerateExports(targetLib);
    // for (const iterator of exports) {
    //     console.log(JSON.stringify(iterator))
    // }

    // 枚举符号 非导出函数要在这里找
    const symbols = Module.enumerateSymbols(targetLib);
    for (const iterator of symbols) {
        // if (iterator.name === "ll11lll1l1" && iterator.type === "function") {
        // target function
        if (iterator.name === "ll11lll1l1") {
            const targetFuncAddr = iterator.address;
            Interceptor.attach(targetFuncAddr, {
                onLeave: function (result) {
                    console.log('key: ', result.readCString());
                },
            });
        }

        // another function
        if (iterator.name === "ll11l1l1l1") {
            const targetFuncAddr = iterator.address;
            Interceptor.attach(targetFuncAddr, {
                onLeave: function (result) {
                    console.log('iv: ', result.readUtf8String());
                },
            });
        }
    }

}

// 这里最好设置延迟 否则可能加载不到
setTimeout(HookNative, 3000);