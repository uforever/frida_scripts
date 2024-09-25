function main() {

    const module = Process.mainModule;
    console.log(JSON.stringify(module));

    const xxteaEncrypt = module.base.add(0x12F5);
    const xxteaDecrypt = module.base.add(0x1456);

    Interceptor.attach(xxteaDecrypt, {
        onEnter: function (_args) {
            console.log("xxtea_decrypt called");
        },
    });

    const xxtea_encrypt = new NativeFunction(xxteaEncrypt, 'int', ['pointer', 'int', 'int']);
    const xxtea_decrypt = new NativeFunction(xxteaDecrypt, 'int', ['pointer', 'int', 'int']);

    Interceptor.replace(
        xxtea_encrypt,
        xxtea_decrypt,
    );

    Interceptor.attach(module.base.add(0x1596), {
        onEnter: function (args) {
            const outputPath = args[0].add(5);
            args[0] = args[1];
            args[1] = outputPath;

            // 输入变成了 message.txt.enc
            console.log('Argument 1: ' + args[0].readUtf8String());
            // 输出变成了 passwd
            console.log('Argument 2: ' + args[1].readUtf8String());
            // console.log('Argument 3: ' + args[2]);
        },
    });

}

setImmediate(main);
