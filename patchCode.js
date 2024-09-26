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

                /*
                // 以JNI_OnLoad为例
                const jniOnload = Module.findExportByName(targetLib, "JNI_OnLoad");
                console.log("[hit JNI_OnLoad]: " + jniOnload);
                // 如果有输出的话 说明检测点在JNI_OnLoad之中或者之后
                // 否则可能在.init_proc .init_array .init_xxx等函数中
                Interceptor.attach(jniOnload, {
                    onEnter: function (_args) {
                        // 反编译发现其中有检测frida和端口的代码
                        // 可以通过修改端口和使用魔改server绕过
                        // 还创建了一个线程 检测是否有java层hook
                        // hook后 & 0x80000 != 0
                        console.log("[func invoke]: JNI_OnLoad");
                    },
                });
                

                // 目标函数名
                const funcAddr = Module.findExportByName(targetLib, "Java_com_r0ysue_test1_MainActivity_stringFromJNI");
                console.log("[hit target func]: " + funcAddr);
                Interceptor.attach(funcAddr, {
                    onEnter: function (_args) {
                        // 其中存在通过特征值0xd61f020058000050
                        // 检测pthread_create是否被hook
                        console.log("[func invoke]: Java_com_r0ysue_test1_MainActivity_stringFromJNI");
                    },
                });
                */


                /*
                // 查看是否有新的线程被创建
                Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
                    onEnter(args) {
                        // 先获取到线程函数的地址 也就是pthread_create的第三个参数
                        // 再计算偏移 这里是0x10448 后续对其进行置空
                        // 取消对pthread_create的hook 以免后续被检测
                        const threadFuncAddr = args[2];
                        console.log("The thread function address is " + ptr(threadFuncAddr).sub(baseAddr));
                    }
                });
                */

                /*
                const newThreadFunc = baseAddr.add(0x10448);
                console.log(Process.pageSize);
                Memory.patchCode(newThreadFunc, 0x3c, function (code) {
                    const codeWriter = new Arm64Writer(code, { pc: newThreadFunc });
                    codeWriter.putNop();
                    codeWriter.flush();
                });
                */

                // 上述方式会报错
                // 将调用pthread_create的指令nop掉
                // .text:0000000000010984 4B F7 FF 97                   BL              .pthread_create
                const newThreadFunc = baseAddr.add(0x10984);
                Memory.patchCode(newThreadFunc, 0x4, function (code) {
                    const codeWriter = new Arm64Writer(code, { pc: newThreadFunc });
                    codeWriter.putNop();
                    codeWriter.flush();
                });

                // hook strstr
                // strstr(v2, "frida")
                // strstr(v2, ":69A2")
                Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {
                    onEnter: function (args) {
                        const keyWord = args[1].readCString();
                        if (keyWord.includes("frida") || keyWord.includes(":69A2")) {
                            this.isCheck = true;
                        }
                    },
                    onLeave: function (retval) {
                        if (this.isCheck) {
                            retval.replace(0);
                            this.isCheck = false;
                        }
                    }
                });

                // hook access
                // access("/data/local/tmp/re.frida.server", 0)
                Interceptor.attach(Module.findExportByName("libc.so", "access"), {
                    onEnter: function (args) {
                        const path = args[0].readCString();
                        if (path.includes("re.frida.server")) {
                            this.isCheck = true;
                        }
                    },
                    onLeave: function (retval) {
                        if (this.isCheck) {
                            retval.replace(-1);
                            this.isCheck = false;
                        }
                    },
                });
            }
        }
    });

    Java.perform(() => {
        const MainActivity = Java.use("com.r0ysue.test1.MainActivity");
        MainActivity.mystr.implementation = function () {
            return true;
        };
    });
}

setImmediate(main);
