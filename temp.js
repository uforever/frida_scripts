const targetLib = "libnative-lib.so";

function main() {
    // 先通过dlopen探索具体是哪个so文件在反frida调试
    const adeAddr = Module.findExportByName(null, "android_dlopen_ext");
    Interceptor.attach(adeAddr, {
        onEnter: function (args) {
            const pathptr = args[0];
            this.isTarget = false;
            if (pathptr) {
                const path = ptr(pathptr).readCString();
                console.log("[dylib open]: ", path);
                if (path.includes(targetLib)) {
                    this.isTarget = true;
                }
            }
        },
        onLeave: function () {
            // 对这个so文件的符号进行hook 看看具体是哪个函数引起的崩溃
            if (this.isTarget) {
                const baseAddr = Module.findBaseAddress(targetLib);
                console.log("[dylib base address]: ", baseAddr);

                // 查看是否有新的线程被创建
                Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
                    onEnter(args) {
                        const threadFuncAddr = args[2];
                        console.log("The thread function address is " + ptr(threadFuncAddr).sub(baseAddr));

                        // const pthreadFunc = args[2];
                        // try {
                        //     const module = Process.getModuleByAddress(pthreadFunc);
                        //     if (module.name === targetLib) {
                        //         console.log("pthread create by target lib, func addr: ", pthreadFunc);
                        //         // 替换反调试函数
                        //         Interceptor.replace(pthreadFunc, new NativeCallback(function () {
                        //             console.log("bypass anti-debug function");
                        //             return 0;
                        //         }, 'int', []));
                        //     }
                        // } catch (_e) {
                        // }
                    }
                })

                // 以JNI_OnLoad为例
                const jniOnload = Module.findExportByName(targetLib, "JNI_OnLoad");
                console.log("[hit JNI_OnLoad]: " + jniOnload);
                // 如果有输出的话 说明检测点在JNI_OnLoad之中或者之后
                // 否则可能在.init_proc .init_array .init_xxx等函数中
                Interceptor.attach(jniOnload, {
                    onEnter: function (_args) {
                        console.log("[func invoke]: JNI_OnLoad");
                    },
                });

                // 目标函数名
                const funcAddr = Module.findExportByName(targetLib, "Java_com_r0ysue_test1_MainActivity_stringFromJNI");
                console.log("[hit target func]: " + funcAddr);
                Interceptor.attach(funcAddr, {
                    onEnter: function (_args) {
                        console.log("[func invoke]: Java_com_r0ysue_test1_MainActivity_stringFromJNI");
                    },
                })

            }
        }
    });

    // Java.perform(() => {
    //     const MainActivity = Java.use("com.r0ysue.test1.MainActivity");
    //     MainActivity.mystr.implementation = function () {
    //         return true;
    //     }
    // });
}

setImmediate(main);
