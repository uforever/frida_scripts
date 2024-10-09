function main() {
    Java.perform(function () {
        const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');

        // 创建了一个自定义的类 MyTrustManager 覆盖 SSL/TLS 证书的验证逻辑 
        const MyTrustManager = Java.registerClass({
            name: "MyTrustManager",
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
        // 创建一个 MyTrustManager 的实例
        const myTrustManagerInstance = MyTrustManager.$new();

        // 使用 SSLContext 创建一个 TLS 上下文
        const sslContext = Java.use("javax.net.ssl.SSLContext").getInstance("TLS");
        // 将刚才创建的 TrustAllManager 作为信任管理器进行初始化
        const trustManagers = Java.array("Ljavax.net.ssl.X509TrustManager;", [myTrustManagerInstance]);
        sslContext.init(null, trustManagers, null);
        // 获取 SSLSocketFactory，允许创建 SSL 套接字
        const sslSocketFactory = sslContext.getSocketFactory();

        // 需要 hook OkHttpClient.Builder 的方法
        const OkHttpClientBuilder = Java.use("okhttp3.OkHttpClient$Builder");

        // Hook OkHttpClient.Builder 中的 sslSocketFactory 方法。
        // 当构造 OkHttpClient 时打印日志，并返回信任所有证书的 SSLSocketFactory
        OkHttpClientBuilder.sslSocketFactory.overload('javax.net.ssl.SSLSocketFactory', 'javax.net.ssl.X509TrustManager').implementation = function (arg0, arg1) {
            console.log("okhttp3.OkHttpClient$Builder.sslSocketFactory() called");
            // 这里有两个参数，是因为OkHttpClient 的设计允许用户直接传入自定义的 TrustManager，以便于灵活性
            return this.sslSocketFactory(sslSocketFactory, myTrustManagerInstance);
        };

        // 自定义 HostnameVerifier
        // 打印日志 但不做验证 直接返回 true
        const HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        const MyHostnameVerifier = Java.registerClass({
            name: "MyHostnameVerify",
            implements: [HostnameVerifier],
            methods: {
                verify(hostname, _ssl_session) {
                    console.log(`verify hostname: ${hostname}`);
                    return true;
                },
            },
        });
        const myHostnameVerifierInstance = MyHostnameVerifier.$new();

        // Hook OkHttpClient.Builder 的 build 方法。
        // 在构建 OkHttpClient 时设置自定义的 HostnameVerifier
        OkHttpClientBuilder.build.implementation = function () {
            this.hostnameVerifier(myHostnameVerifierInstance);
            return this.build();
        };
    });
}

setImmediate(main);
