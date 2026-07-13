// Java.perform(() => {
//     const groups = Java.enumerateMethods('*X509Certificate*!getExtensionValue*');
//     console.log(JSON.stringify(groups, null, 2));
// });
// 找到目标类
// org.bouncycastle.jcajce.provider.asymmetric.x509.X509CertificateImpl
// com.google.android.gms.org.conscrypt.OpenSSLX509Certificate

// 全局搜索、加载目标类
function useClass(klass) {
    for (const loader of Java.enumerateClassLoadersSync()) {
        try {
            loader.findClass(klass);
            return Java.ClassFactory.get(loader).use(klass);
        } catch (e) {
            continue;
        }
    }
    throw new Error(`${klass} not found`);
}

function doJavaHook() {
    const x509cert = useClass("com.google.android.gms.org.conscrypt.OpenSSLX509Certificate");
    x509cert.getExtensionValue.overload('java.lang.String').implementation = function (str) {
        var retval = this.getExtensionValue(str);
        console.log(`[!] getExtensionValue(str) called
- str: ${str}
- retval: ${retval == null ? "" : retval.toString()}`);

        // 不通用 需要具体分析
        // if (retval != null && str == "1.3.6.1.4.1.11129.2.1.17") {
        //     retval[191] = 1; // deviceLocked  BOOLEAN
        //     retval[194] = 0; // Verified  (0),    SelfSigned  (1),    Unverified  (2),    Failed  (3),
        // }
        return retval;
    };
}

// Java.perform(doJavaHook);

// hook时机
function main() {
    Java.perform(function () {
        const cl = Java.use("java.lang.ClassLoader");
        cl.loadClass.overload('java.lang.String', 'boolean').implementation = function (className, resolve) {
            const retval = this.loadClass(className, resolve);
            if (className.includes("com.google.android.gms.org.conscrypt.OpenSSLX509Certificate")) {
                Java.perform(doJavaHook);
            }
            return retval;
        };
    });
}

setImmediate(main);
