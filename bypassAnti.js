const targetLib = "libmsaoaidsec.so";
let alreadyHook = false;

function main() {
    const adeAddr = Module.findExportByName(null, "android_dlopen_ext");
    Interceptor.attach(adeAddr, {
        onEnter: function (args) {
            const pathptr = args[0];
            this.isTarget = false;
            if (pathptr) {
                const path = ptr(pathptr).readCString();
                console.log("[dylib open]: ", path);

                if (path.includes(targetLib)) {
                    hook_init_proc();
                    this.isTarget = true;
                }
            }
        },
    });
}

function hook_init_proc() {
    const linker = (Process.pointerSize == 8) ? Process.findModuleByName("linker64") : Process.findModuleByName("linker");
    if (linker) {
        // hook call_constructors 函数
        const symbols = linker.enumerateSymbols();
        for (const symbol of symbols) {
            if (symbol.name.includes("call_constructors")) {
                Interceptor.attach(symbol.address, {
                    onEnter: function (_args) {
                        if (!alreadyHook) {
                            const targetSo = Process.findModuleByName(targetLib);
                            if (targetSo) {
                                hook_before_init_proc(targetSo);
                                alreadyHook = true;
                            }
                        }
                    }
                });
                break;
            }
        }
    }
}

function hook_before_init_proc(targetSo) {
    const baseAddr = targetSo.base;
    console.log("targetSo.base: " + baseAddr);

    nop(baseAddr, 0x1C544);
    nop(baseAddr, 0x1B8D4);
    nop(baseAddr, 0x26E5C);

    generalBypassHook();

    // hook pthread_create 函数
    Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
        onEnter(args) {
            const threadFuncAddr = args[2];
            console.log("The thread function address is " + ptr(threadFuncAddr).sub(baseAddr));
        }
    });
    /*
    [dylib open]:  /system/framework/oat/arm64/org.apache.http.legacy.odex
    [dylib open]:  /data/app/~~Hu9R_ySuFoCUOt4uZED-ig==/cn.soulapp.android-V18oODwiM_xA47Z6dBWmaQ==/oat/arm64/base.odex
    [dylib open]:  /data/app/~~Hu9R_ySuFoCUOt4uZED-ig==/cn.soulapp.android-V18oODwiM_xA47Z6dBWmaQ==/lib/arm64/libmmkv.so
    [dylib open]:  /data/app/~~Hu9R_ySuFoCUOt4uZED-ig==/cn.soulapp.android-V18oODwiM_xA47Z6dBWmaQ==/lib/arm64/libsoul-analytics.so
    [dylib open]:  /data/app/~~Hu9R_ySuFoCUOt4uZED-ig==/cn.soulapp.android-V18oODwiM_xA47Z6dBWmaQ==/lib/arm64/libapminsighta.so
    [dylib open]:  /data/app/~~Hu9R_ySuFoCUOt4uZED-ig==/cn.soulapp.android-V18oODwiM_xA47Z6dBWmaQ==/lib/arm64/libfdsan.so
    [dylib open]:  /data/app/~~Hu9R_ySuFoCUOt4uZED-ig==/cn.soulapp.android-V18oODwiM_xA47Z6dBWmaQ==/lib/arm64/libvolc_log.so
    [dylib open]:  /data/app/~~Hu9R_ySuFoCUOt4uZED-ig==/cn.soulapp.android-V18oODwiM_xA47Z6dBWmaQ==/lib/arm64/libmsaoaidsec.so
    targetSo.base: 0x787018f000
    The thread function address is 0x78701ab544     // sub_1C544
    The thread function address is 0x78701aa8d4     // sub_1B8D4
    The thread function address is 0x78701b5e5c     // sub_26E5C
    */
}


function nop(base, offset) {
    Interceptor.replace(base.add(offset), new NativeCallback(function () {
        console.log(`${offset} thread func noped`)
    }, 'void', []));
}

function generalBypassHook() {
    // hook fgets 函数
    const fgetsPtr = Module.findExportByName("libc.so", "fgets");
    const fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
    Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
        const retval = fgets(buffer, size, fp);
        const bufstr = Memory.readUtf8String(buffer);
        if (bufstr.includes("TracerPid:")) {
            Memory.writeUtf8String(buffer, "TracerPid:\t0");
            console.log("tracerpid replaced: " + Memory.readUtf8String(buffer));
        }
        return retval;
    }, 'pointer', ['pointer', 'int', 'pointer']));

    // hook strstr 函数
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

    // hook access函数
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

setImmediate(main);
