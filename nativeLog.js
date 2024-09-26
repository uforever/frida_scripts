const targetLib = "libregister.so";

function main() {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
        {
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
            onLeave: function (_retval) {
                if (this.isTarget) {

                    const baseAddr = Module.findBaseAddress(targetLib);
                    console.log("[target lib base address]: ", baseAddr);

                    // 第一次加密
                    Interceptor.attach(baseAddr.add(0x26EC), {
                        onEnter: function (args) {
                            const input = args[0].readCString();
                            this.output = args[2];
                            console.log("[func enter]: sub_26EC");
                            console.log("[input]: ", input);
                        },
                        onLeave: function (_retval) {
                            console.log("[func leave]: sub_26EC");
                            console.log("[output]: ", ptr(this.output).readByteArray(16));
                        },
                    });

                    // 第二次加密
                    Interceptor.attach(baseAddr.add(0x1AA4), {
                        onEnter: function (args) {
                            this.output = args[1];
                            console.log("[func enter]: sub_1AA4");
                        },
                        onLeave: function (_retval) {
                            console.log("[func leave]: sub_1AA4");
                            // 这里长度不确定 可以通过前几位判断算法类型
                            console.log("[output]: ", ptr(this.output).readByteArray(16));
                        },
                    });

                    // 第三次加密
                    Interceptor.attach(baseAddr.add(0xA0C), {
                        onEnter: function (args) {
                            const len = args[1].toUInt32();
                            const input = args[0].readByteArray(len);
                            this.output = args[2];
                            console.log("[func enter]: sub_A0C");
                            console.log("[input]: ", input);
                        },
                        onLeave: function (_retval) {
                            console.log("[func leave]: sub_A0C");
                            console.log("[output]: ", ptr(this.output).readCString());
                        },
                    });
                }
            }
        }
    );
}

setImmediate(main);
