const targetLib = "libdemo3.so";

function HookNative() {
    console.log("-------- Start Hooking --------");

    const dlopenAddr = Module.findExportByName(null, "dlopen");
    Interceptor.attach(dlopenAddr, {
        onEnter: function (args) {
            const pathptr = args[0];
            if (pathptr) {
                // 读取字符串写法1 两种方式都可以
                const path = Memory.readCString(pathptr);
                console.log("dlopen called with: " + path);
            }
        },
    });

    const adeAddr = Module.findExportByName(null, "android_dlopen_ext");
    Interceptor.attach(adeAddr, {
        onEnter: function (args) {
            const pathptr = args[0];
            this.isTarget = false;
            if (pathptr) {
                // 读取字符串写法2 两种方式都可以
                const path = ptr(pathptr).readCString();
                console.log("android_dlopen_ext called with: ", path);
                if (path.includes(targetLib)) {
                    // 命中目标库 标记上
                    this.isTarget = true;
                }
            }
        },
        onLeave: function () {
            // 如果是目标库
            if (this.isTarget) {
                // 目标函数名
                const funcAddr = Module.findExportByName(targetLib, "Java_com_example_demo3_MainActivity_getStringLengthFromJNI");
                console.log("target function at " + funcAddr);

                // 参数篡改
                const oldFunc = new NativeFunction(funcAddr, 'int', ['pointer', 'pointer', 'pointer']);
                const newFunc = new NativeCallback(function (env, thiz, str) {
                    console.log("\t[key argument]: ", Java.vm.tryGetEnv().getStringUtfChars(str, null).readCString());
                    const newInput = Java.vm.tryGetEnv().newStringUtf("空山新雨后");
                    const newRetVal = oldFunc(env, thiz, newInput);
                    // console.log("\t[return value]: ", newRetVal);
                    return newRetVal;
                }, 'int', ['pointer', 'pointer', 'pointer']);
                Interceptor.replace(oldFunc, newFunc);
            }
        }
    });
}

setImmediate(HookNative);