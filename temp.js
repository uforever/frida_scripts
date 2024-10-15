let classFactory = null;
// 如果OkHttp被混淆了 需要手动反编译找到混淆后的包名
// 可以通过手动搜索关键字查找 如
// OkHttpClient CertificatePinner
// const okHttpPackageName = "nl";
const okHttpPackageName = "okhttp3";

let customTrustManager = null;
let customSslSocketFactory = null;
let customHostnameVerifier = null;

function main() {
    Java.perform(() => {
        // 没有壳
        // classFactory = Java;
        // sslUnpinning();

        // 有壳
        const Application = Java.use("android.app.Application");
        Application.attach.overload("android.content.Context").implementation = function (context) {
            this.attach(context);
            const classLoader = context.getClassLoader();
            classFactory = Java.ClassFactory.get(classLoader);
            sslUnpinning();
        };
    });
}

function classExists(className) {
    try {
        const targetClass = classFactory.use(className);
        return [true, targetClass];
    } catch (_err) {
        return [false, null];
    }
}

function initCustomClasses() {
    try {
        // 准备两个自定义参数 customTrustManager 和 customSslSocketFactory
        const X509TrustManager = classFactory.use('javax.net.ssl.X509TrustManager');
        // 创建了一个自定义的类 CustomTrustManager 覆盖 SSL/TLS 证书的验证逻辑 
        const CustomTrustManager = classFactory.registerClass({
            name: "CustomTrustManager",
            implements: [X509TrustManager],
            methods: {
                // 当客户端证书被检查时调用，什么都不做，仅打印日志。
                checkClientTrusted(_chain, _authType) {
                    console.log("check client trusted called");
                },
                // 当服务器证书被检查时调用，同样什么都不做，仅打印日志。
                checkServerTrusted(_chain, _authType) {
                    console.log("check server trusted called");
                },
                // 返回一个空数组，表示接受所有的证书颁发机构。
                getAcceptedIssuers() {
                    return [];
                },
            },
        });
        // 创建一个 CustomTrustManager 的实例
        customTrustManager = function () {
            return CustomTrustManager.$new();
        };

        // 使用 SSLContext 创建一个 TLS 上下文
        const sslContext = classFactory.use("javax.net.ssl.SSLContext");
        const tlsInstance = sslContext.getInstance("TLS");
        // 将刚才创建的 TrustAllManager 作为信任管理器进行初始化
        const trustManagers = classFactory.array("Ljavax.net.ssl.X509TrustManager;", [customTrustManager()]);
        tlsInstance.init(null, trustManagers, null);
        // 获取 SSLSocketFactory，允许创建 SSL 套接字
        customSslSocketFactory = function () {
            return tlsInstance.getSocketFactory();
        };

        // 准备自定义参数 customHostnameVerifier
        const HostnameVerifier = classFactory.use("javax.net.ssl.HostnameVerifier");
        const CustomHostnameVerifier = classFactory.registerClass({
            name: "CustomHostnameVerifier",
            implements: [HostnameVerifier],
            methods: {
                verify(hostname, _ssl_session) {
                    // 打印日志 但不做验证 直接返回 true
                    console.log(`verify hostname: ${hostname}`);
                    return true;
                },
            },
        });
        customHostnameVerifier = function () {
            return CustomHostnameVerifier.$new();
        };
    } catch (_e) { }
}

function sslUnpinning() {
    initCustomClasses();

    hookOkHttp();

    // 安卓本身自带的公钥固定的方法也需要hook
    const targetNSTM = "android.security.net.config.NetworkSecurityTrustManager";
    const [NetworkSecurityTrustManagerExists, NetworkSecurityTrustManager] = classExists(targetNSTM);
    if (NetworkSecurityTrustManagerExists) {
        NetworkSecurityTrustManager.checkPins.implementation = function () {
            console.log("android.security.net.config.NetworkSecurityTrustManager.checkPins() called");
        };
    }

    const targetTMI = "com.android.org.conscrypt.TrustManagerImpl";
    const [TrustManagerImplExists, TrustManagerImpl] = classExists(targetTMI);
    if (TrustManagerImplExists) {
        // hook 其中 checkServerTrusted 和 checkTrusted 方法
        const ArrayList = classFactory.use('java.util.ArrayList');
        const emptyArrayList = function () {
            return ArrayList.$new();
        };
        try {
            TrustManagerImpl.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String').implementation = function (_v0, _v1, _v2) {
                console.log("com.android.org.conscrypt.TrustManagerImpl.checkServerTrusted('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String') called");
                return emptyArrayList();
            };
        } catch (_err) { }

        try {
            TrustManagerImpl.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (_v0, _v1, _v2) {
                console.log("com.android.org.conscrypt.TrustManagerImpl.checkServerTrusted('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'javax.net.ssl.SSLSession') called");
                return emptyArrayList();
            };
        } catch (_err) { }

        try {
            TrustManagerImpl.checkTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String', 'boolean').implementation = function (_v0, _v1, _v2, _v3) {
                console.log("com.android.org.conscrypt.TrustManagerImpl.checkTrusted('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String', 'boolean') called");
                return emptyArrayList();
            };
        } catch (_err) { }

        try {
            TrustManagerImpl.checkTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'javax.net.ssl.SSLSession', 'javax.net.ssl.SSLParameters', 'boolean').implementation = function (_v0, _v1, _v2, _v3, _v4) {
                console.log("com.android.org.conscrypt.TrustManagerImpl.checkTrusted('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'javax.net.ssl.SSLSession', 'javax.net.ssl.SSLParameters', 'boolean') called");
                return emptyArrayList();
            };

        } catch (_err) { }

        try {
            TrustManagerImpl.checkTrusted.overload('[Ljava.security.cert.X509Certificate;', '[B', '[B', 'java.lang.String', 'java.lang.String', 'boolean').implementation = function (_v0, _v1, _v2, _v3, _v4, _v5) {
                console.log("com.android.org.conscrypt.TrustManagerImpl.checkTrusted('[Ljava.security.cert.X509Certificate;', '[B', '[B', 'java.lang.String', 'java.lang.String', 'boolean') called");
                return emptyArrayList();
            };
        } catch (_err) { }
    }

    const targetCP = "com.android.org.conscrypt.Platform";
    const [PlatformExists, Platform] = classExists(targetCP);
    if (PlatformExists) {
        try {
            Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.OpenSSLEngineImpl').implementation = function (_v0, _v1, _v2, _v3) {
                console.log("com.android.org.conscrypt.Platform.checkServerTrusted('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.OpenSSLEngineImpl') called");
            };
        } catch (_err) { }

        try {
            Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.OpenSSLSocketImpl').implementation = function (_v0, _v1, _v2, _v3) {
                console.log("com.android.org.conscrypt.Platform.checkServerTrusted('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.OpenSSLSocketImpl') called");
            };
        } catch (_err) { }


        try {
            Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.AbstractConscryptSocket').implementation = function (_v0, _v1, _v2, _v3) {
                console.log("com.android.org.conscrypt.Platform.checkServerTrusted(javax.net.ssl.X509TrustManager,java.security.cert.X509Certificate[],java.lang.String,com.android.org.conscrypt.AbstractConscryptSocket) called");
            };
        } catch (_err) { }

        try {
            Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.ConscryptEngine').implementation = function (_v0, _v1, _v2, _v3) {
                console.log("com.android.org.conscrypt.Platform.checkServerTrusted(javax.net.ssl.X509TrustManager,java.security.cert.X509Certificate[],java.lang.String,com.android.org.conscrypt.ConscryptEngine) called");
            };
        } catch (_err) { }
    }

    const targetPTM = "appcelerator.https.PinningTrustManager";
    const [PinningTrustManagerExists, PinningTrustManager] = classExists(targetPTM);
    if (PinningTrustManagerExists) {
        try {
            PinningTrustManager.checkServerTrusted.overload().implementation = function () {
                console.log("appcelerator.https.PinningTrustManager.checkServerTrusted() called");
            }
        } catch (_err) { }
    }

    const targetRP = "org.xutils.http.RequestParams";
    const [RequestParamsExists, RequestParams] = classExists(targetRP);
    if (RequestParamsExists) {
        try {
            // 对 setSslSocketFactory 和 setHostnameVerifier 两个方法进行hook
            RequestParams.setSslSocketFactory.overload('javax.net.ssl.SSLSocketFactory').implementation = function (_v0) {
                this.setSslSocketFactory(customSslSocketFactory());
            };

            RequestParams.setHostnameVerifier.overload('javax.net.ssl.HostnameVerifier').implementation = function (_v0) {
                this.setHostnameVerifier(customHostnameVerifier());
            };
        } catch (_err) { }
    }
}

function hookOkHttp() {
    // 如果使用了OkHttp
    const targetOkHttpClassName = `${okHttpPackageName}.OkHttpClient$Builder`;
    const [OkHttpClientBuilderExists, OkHttpClientBuilder] = classExists(targetOkHttpClassName);
    if (OkHttpClientBuilderExists) {
        // OkHttp Customizing Trusted Certificates 示例
        // https://square.github.io/okhttp/features/https/#customizing-trusted-certificates-kt-java

        // trustManager = trustManagerForCertificates(trustedCertificatesInputStream());
        // SSLContext sslContext = SSLContext.getInstance("TLS");
        // sslContext.init(null, new TrustManager[] { trustManager }, null);
        // sslSocketFactory = sslContext.getSocketFactory();
        // client = new OkHttpClient.Builder().sslSocketFactory(sslSocketFactory, trustManager).build();

        // 关键就是最后一行的 sslSocketFactory(sslSocketFactory, trustManager) 和 build() 两个方法
        // sslSocketFactory 方法需要替换掉两个参数
        // build 方法调用前需要替换掉hostnameVerifier


        // OkHttp Certificate Pinning 示例
        // https://square.github.io/okhttp/features/https/#certificate-pinning-kt-java

        // client = new OkHttpClient.Builder()
        //   .certificatePinner(
        //       new CertificatePinner.Builder()
        //           .add("publicobject.com", "sha256/afwiKY3RxoMmLkuRW1l7QsPZTJPwDS2pdDROQjXw8ig=")
        //           .build())
        //   .build();

        // 关键是 certificatePinner 方法
        // 可以返回 OkHttpClient$Builder 本身 不做任何处理


        // 分别 hook OkHttpClient$Builder 的三个方法
        // sslSocketFactory()
        // build()
        // certificatePinner()

        // Hook OkHttpClient$Builder 中的 sslSocketFactory 方法 替换掉两个参数
        // 当构造 OkHttpClient 时打印日志，并返回信任所有证书的 SSLSocketFactory
        OkHttpClientBuilder.sslSocketFactory.overload('javax.net.ssl.SSLSocketFactory', 'javax.net.ssl.X509TrustManager').implementation = function (_sslSocketFactory, _trustManager) {
            console.log("okhttp3.OkHttpClient$Builder.sslSocketFactory() called");
            // 这里有两个参数，是因为OkHttpClient 的设计允许用户直接传入自定义的 TrustManager，以便于灵活性
            return this.sslSocketFactory(customSslSocketFactory(), customTrustManager());
        };

        // Hook OkHttpClient$Builder 的 build 方法
        // 调用前替换hostnameVerifier
        OkHttpClientBuilder.build.implementation = function () {
            console.log("okhttp3.OkHttpClient$Builder.build() called");
            this.hostnameVerifier(customHostnameVerifier());
            return this.build();
        };

        // Hook OkHttpClient$Builder 的 certificatePinner 方法
        // 不做处理 返回builder本身
        OkHttpClientBuilder.certificatePinner.implementation = function (_certificatePinner) {
            console.log("okhttp3.OkHttpClient$Builder.certificatePinner() called");
            return classFactory.retain(this);
        };

    }
}

setImmediate(main);
