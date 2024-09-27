const libName = "native-lib";
const targetLib = `lib${libName}.so`;

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
                    this.isTarget = true;
                }
            }
        },
        onLeave: function () {
            if (this.isTarget) {
                // const baseAddr = Module.findBaseAddress(targetLib);
                // console.log("[dylib base address]: ", baseAddr);

                // // 这里 libcrypto.so 就是 openssl 库
                // const opensslAddr = Module.findBaseAddress("libcrypto.so");
                // console.log("[openssl base address]: ", opensslAddr);

                // 导入的函数可以直接在这里hook
                Interceptor.attach(Module.findExportByName(targetLib, "EVP_EncryptUpdate"), {
                    onEnter: function (args) {
                        this.out = args[1];
                        this.outl = args[2];
                        const inl = args[4].toUInt32();
                        console.log("[onEnter] EVP_EncryptUpdate");
                        console.log(`input(${inl}):\n${hexdump(args[3],
                            {
                                offset: 0,
                                length: inl,
                                header: true,
                                ansi: true
                            }
                        )}\n`);
                    },
                    onLeave: function (_retval) {
                        console.log("[onLeave] EVP_EncryptUpdate");
                        const outl = ptr(this.outl).readInt();
                        console.log(`output(${outl}):\n${hexdump(this.out, {
                            offset: 0,
                            length: outl,
                            header: true,
                            ansi: true
                        })}\n`);
                    },
                });

                Interceptor.attach(Module.findExportByName(targetLib, "EVP_EncryptFinal"), {
                    onEnter: function (args) {
                        this.out = args[1];
                        this.outl = args[2];
                    },
                    onLeave: function (_retval) {
                        console.log("[onLeave] EVP_EncryptFinal");
                        const outl = ptr(this.outl).readInt();
                        console.log(`output(${outl}):\n${hexdump(this.out, {
                            offset: 0,
                            length: outl,
                            header: true,
                            ansi: true
                        })}\n`);
                    },
                });

                Interceptor.attach(Module.findExportByName(targetLib, "EVP_EncodeUpdate"), {
                    onEnter: function (args) {
                        console.log("[onEnter] EVP_EncodeUpdate");
                        const inl = args[4].toUInt32();
                        console.log(`input(${inl}):\n${hexdump(args[3],
                            {
                                offset: 0,
                                length: inl,
                                header: true,
                                ansi: true
                            }
                        )}\n`);
                    },
                });

                Interceptor.attach(Module.findExportByName(targetLib, "EVP_EncodeFinal"), {
                    onEnter: function (args) {
                        this.out = args[1];
                        this.outl = args[2];
                    },
                    onLeave: function (_retval) {
                        console.log("[onLeave] EVP_EncodeFinal");
                        console.log(`output(${ptr(this.outl).readInt()}): ${this.out.readCString()}\n`);
                    },
                });

                // 未被导入的函数仍需要通过libcrypto.so来hook
                Interceptor.attach(Module.findExportByName("libcrypto.so", "AES_set_encrypt_key"), {
                    onEnter: function (args) {
                        console.log("[onEnter] AES_set_encrypt_key");
                        this.keyLen = args[1].toInt32() / 8;
                        this.aesKey = args[2];
                        console.log(`input: ${args[0].readCString()}\n`);
                    },
                    onLeave: function (_retval) {
                        console.log("[onLeave] AES_set_encrypt_key");
                        console.log(`output(${this.keyLen}):\n${hexdump(this.aesKey, {
                            offset: 0,
                            length: this.keyLen,
                            header: true,
                            ansi: true
                        })}\n`);
                    }
                });

                Interceptor.attach(Module.findExportByName("libcrypto.so", "AES_encrypt"), {
                    onEnter: function (args) {
                        console.log("[onEnter] AES_encrypt");
                        const aesKey = args[2];
                        console.log(`AES_KEY: ${hexdump(aesKey, {
                            offset: 0,
                            length: 16,
                            header: true,
                            ansi: true
                        })}\n`);
                    },
                });
            }
        }
    });
}

setImmediate(main);
