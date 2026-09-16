# SSL Unpinning、证书导出与流量抓取

抓包绕过优先使用 spawn 注入。hook 顺序：`SSLContext.init()` → OkHttp → Conscrypt → 系统组件 → Apache/Xutils 等其它框架。

## 1. SSL unpinning 核心：TrustAll + SSLContext

自定义 TrustManager（空验证）与 HostnameVerifier，替换 SSLContext 初始化。带壳应用必须用应用 ClassLoader 的 classFactory（无壳传 `Java`）：

```javascript
let classFactory = null;

function doJavaHook() {
  const Application = Java.use("android.app.Application");
  Application.attach.overload("android.content.Context").implementation = function (context) {
    this.attach(context);
    const classLoader = context.getClassLoader();
    classFactory = Java.ClassFactory.get(classLoader);
  };
  if (!classFactory) {
    classFactory = Java;   // 无壳
  }
  sslUnpinning();
}

function classExists(className) {
  try {
    const targetClass = classFactory.use(className);
    return [true, targetClass];
  } catch (_err) {
    return [false, null];
  }
}

function customInit() {
  try {
    const ArrayList = classFactory.use('java.util.ArrayList');
    const customArrayList = function () { return ArrayList.$new(); };

    // 自定义 TrustManager 覆盖证书验证逻辑
    const X509TrustManager = classFactory.use('javax.net.ssl.X509TrustManager');
    const CustomTrustManager = classFactory.registerClass({
      name: "CustomTrustManager",
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted(_chain, _authType) {},
        checkServerTrusted(_chain, _authType) {},
        getAcceptedIssuers() { return []; },
      },
    });

    const customTrustManager = function () { return CustomTrustManager.$new(); };
    const customTrustManagers = function () {
      return classFactory.array("Ljavax.net.ssl.X509TrustManager;", [customTrustManager()]);
    };

    // TLS 上下文 + TrustAll 初始化，得到 SSLSocketFactory
    const SSLContext = classFactory.use("javax.net.ssl.SSLContext");
    const customSslContext = function (algorithm) { return SSLContext.getInstance(algorithm); };
    const tlsInstance = customSslContext("TLS");
    tlsInstance.init(null, customTrustManagers(), null);
    const customSslSocketFactory = function () { return tlsInstance.getSocketFactory(); };

    // hook SSLContext.init 替换 TrustManager
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (km, _tm, random) {
      this.init(null, customTrustManagers(), null);
    };

    // 自定义 HostnameVerifier
    const HostnameVerifier = classFactory.use("javax.net.ssl.HostnameVerifier");
    const CustomHostnameVerifier = classFactory.registerClass({
      name: "CustomHostnameVerifier",
      implements: [HostnameVerifier],
      methods: {
        verify(hostname, _ssl_session) {
          return true;
        },
      },
    });
    const customHostnameVerifier = function () { return CustomHostnameVerifier.$new(); };

    // 供其它框架 hook 函数使用，挂到全局
    globalThis.customArrayList = customArrayList;
    globalThis.customTrustManager = customTrustManager;
    globalThis.customTrustManagers = customTrustManagers;
    globalThis.customSslSocketFactory = customSslSocketFactory;
    globalThis.customHostnameVerifier = customHostnameVerifier;
  } catch (err) {
    console.error(err.message);
  }
}
```

## 2. 多框架 unpinning

每个框架 hook 前用 `classExists` 探测（类不存在会抛异常），避免脚本中断。

**Java 标准库**：

```javascript
function hookJavaStuff() {
  const [tmfExists, TrustManagerFactory] = classExists("javax.net.ssl.TrustManagerFactory");
  if (tmfExists) {
    TrustManagerFactory.getTrustManagers.overload().implementation = function () {
      return customTrustManagers();
    };
  }

  const [hucExists, HttpsURLConnection] = classExists("javax.net.ssl.HttpsURLConnection");
  if (hucExists) {
    HttpsURLConnection.setDefaultHostnameVerifier.overload('javax.net.ssl.HostnameVerifier').implementation = function (_v) {};
    HttpsURLConnection.setHostnameVerifier.overload('javax.net.ssl.HostnameVerifier').implementation = function (_v) {};
    HttpsURLConnection.setSSLSocketFactory.overload('javax.net.ssl.SSLSocketFactory').implementation = function (_sf) {};
  }
}
```

**Android 系统组件**（NetworkSecurityTrustManager / X509TrustManagerExtensions / WebView）：

```javascript
function hookAndroidStuff() {
  const [nstmExists, NetworkSecurityTrustManager] = classExists("android.security.net.config.NetworkSecurityTrustManager");
  if (nstmExists) {
    NetworkSecurityTrustManager.checkPins.implementation = function () {};
  }

  const [xtmeExists, X509TrustManagerExtensions] = classExists("android.net.http.X509TrustManagerExtensions");
  if (xtmeExists) {
    X509TrustManagerExtensions.checkServerTrusted.implementation = function (_chain, _authType, _host) {
      return customArrayList();
    };
  }

  const [wvcExists, WebViewClient] = classExists("android.webkit.WebViewClient");
  if (wvcExists) {
    WebViewClient.onReceivedSslError.implementation = function (_view, handler, _error) {
      handler.proceed();
    };
  }
}
```

**OkHttp**（三个关键方法：`sslSocketFactory` 换双参、`build` 前换 hostnameVerifier、`certificatePinner` 原样返回）：

```javascript
function hookOkHttp() {
  // OkHttp 被混淆时：反编译找混淆后的包名（搜 OkHttpClient / CertificatePinner 关键字）
  const [builderExists, OkHttpClientBuilder] = classExists("okhttp3.OkHttpClient$Builder");
  if (builderExists) {
    OkHttpClientBuilder.sslSocketFactory.overload('javax.net.ssl.SSLSocketFactory', 'javax.net.ssl.X509TrustManager').implementation = function (_sslSocketFactory, _trustManager) {
      return this.sslSocketFactory(customSslSocketFactory(), customTrustManager());
    };

    OkHttpClientBuilder.build.implementation = function () {
      this.hostnameVerifier(customHostnameVerifier());
      return this.build();
    };

    OkHttpClientBuilder.certificatePinner.implementation = function (_certificatePinner) {
      return classFactory.retain(this);
    };
  }
}
```

**Conscrypt**（TrustManagerImpl 双重载 + Platform + OpenSSLSocketFactoryImpl 自动发现混淆后的 OkHttp 类）：

```javascript
function hookConscrypt() {
  const [tmiExists, TrustManagerImpl] = classExists("com.android.org.conscrypt.TrustManagerImpl");
  if (tmiExists) {
    TrustManagerImpl.checkTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'javax.net.ssl.SSLSession', 'javax.net.ssl.SSLParameters', 'boolean').implementation = function (_v0, _v1, _v2, _v3, _v4) {
      return customArrayList();
    };
    TrustManagerImpl.checkTrusted.overload('[Ljava.security.cert.X509Certificate;', '[B', '[B', 'java.lang.String', 'java.lang.String', 'boolean').implementation = function (_v0, _v1, _v2, _v3, _v4, _v5) {
      return customArrayList();
    };
  }

  const [cpExists, Platform] = classExists("com.android.org.conscrypt.Platform");
  if (cpExists) {
    Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.AbstractConscryptSocket').implementation = function (_v0, _v1, _v2, _v3) {};
    Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.ConscryptEngine').implementation = function (_v0, _v1, _v2, _v3) {};
  }

  // 通过 OpenSSLSocketFactoryImpl.createSocket 调用栈自动发现混淆后的
  // okhttp RealConnection / Route / Address / CertificatePinner
  const [ossfiExists, OpenSSLSocketFactoryImpl] = classExists("com.android.org.conscrypt.OpenSSLSocketFactoryImpl");
  if (ossfiExists) {
    const searchedPackages = new Set();
    const Modifier = classFactory.use("java.lang.reflect.Modifier");
    for (const createSocket of OpenSSLSocketFactoryImpl.createSocket.overloads) {
      createSocket.implementation = function () {
        const stackTraceElements = classFactory.use("java.lang.Throwable").$new().getStackTrace();
        for (const stElement of stackTraceElements) {
          const stElementClassName = stElement.getClassName();
          if (searchedPackages.has(stElementClassName)) continue;
          searchedPackages.add(stElementClassName);

          const stElementClass = classFactory.use(stElementClassName);
          if (stElementClass.class.getSuperclass().getName() === "java.lang.Object") continue;

          // 按字段特征（1 List + 2 Socket + 1 boolean + 1 long + 2~4 int）过滤出 RealConnection
          let fieldsFinalListCount = 0, fieldsSocketCount = 0, fieldsIntCount = 0,
              fieldsBooleanCount = 0, fieldsLongCount = 0;
          for (const field of stElementClass.class.getDeclaredFields()) {
            const modifiers = field.getModifiers();
            if (Modifier.isStatic(modifiers)) continue;
            const typeName = field.getType().getName();
            if (Modifier.isFinal(modifiers)) {
              if (typeName === "java.util.List") fieldsFinalListCount++; else continue;
            }
            if (typeName === "java.net.Socket") fieldsSocketCount++;
            else if (typeName === "int") fieldsIntCount++;
            else if (typeName === "boolean") fieldsBooleanCount++;
            else if (typeName === "long") fieldsLongCount++;
          }
          if (fieldsFinalListCount !== 1 || fieldsSocketCount !== 2 ||
              fieldsBooleanCount !== 1 || fieldsLongCount !== 1 ||
              (fieldsIntCount !== 2 && fieldsIntCount !== 4)) continue;

          // 唯一构造且两参 → RealConnection；参数[1] → Route；Route参数[0] → Address
          const stElementClassConstructors = stElementClass.class.getDeclaredConstructors();
          if (stElementClassConstructors.length !== 1) continue;
          const ctor = stElementClassConstructors[0];
          const ctorParamTypes = ctor.getParameterTypes();
          if (ctorParamTypes.length !== 2) continue;

          console.log("[class find] maybe okhttp RealConnection: ", stElementClassName);
          const classRoute = ctorParamTypes[1].getName();
          const routeCtors = classFactory.use(classRoute).class.getDeclaredConstructors();
          if (routeCtors.length !== 1) continue;
          const routeParamTypes = routeCtors[0].getParameterTypes();
          if (routeParamTypes.length !== 3) continue;

          const classAddress = routeParamTypes[0].getName();
          const Address = classFactory.use(classAddress);
          const addressCtors = Address.class.getDeclaredConstructors();
          if (addressCtors.length !== 1) continue;
          const addrParamTypes = addressCtors[0].getParameterTypes();
          if (addrParamTypes.length !== 12) continue;

          // hook Address.$init 记录 HostnameVerifier（可能是混淆后的名字）
          Address.$init.implementation = function (
            uriHost, uriPort, dns, socketFactory, sslSocketFactory,
            hostnameVerifier, certificatePinner, authenticator,
            proxy, protocols, connectionSpecs, proxySelector
          ) {
            const classHostnameVerifier = addrParamTypes[5].getName();
            if (classHostnameVerifier !== "javax.net.ssl.HostnameVerifier") {
              console.log("[class find] maybe HostnameVerifier: ", classHostnameVerifier);
            }
            return this.$init(
              uriHost, uriPort, dns, socketFactory, sslSocketFactory,
              hostnameVerifier, certificatePinner, authenticator,
              proxy, protocols, connectionSpecs, proxySelector
            );
          };

          // hook CertificatePinner 的 check(String, List) 方法
          const classCertificatePinner = addrParamTypes[6].getName();
          const CertificatePinner = classFactory.use(classCertificatePinner);
          for (const method of CertificatePinner.class.getDeclaredMethods()) {
            if (method.getReturnType().getName() !== "void") continue;
            const paramTypes = method.getParameterTypes();
            if (paramTypes.length !== 2) continue;
            if (paramTypes[0].getName() !== "java.lang.String") continue;
            if (paramTypes[1].getName() !== "java.util.List") continue;
            const checkMethod = method.getName();
            console.log("[class find] maybe okhttp CertificatePinner check method: ", checkMethod);
            CertificatePinner[checkMethod].overload('java.lang.String', 'java.util.List').implementation = function (_hostname, _certificates) {};
          }
        }
        return createSocket.apply(this, arguments);
      }
    }
  }
}
```

**Apache / Xutils / Appcelerator / ChBoye**（老框架，同样 classExists 探测）：

```javascript
function hookOtherFrameworks() {
  // Apache DefaultHttpClient
  const [dhcExists, DefaultHttpClient] = classExists("org.apache.http.impl.client.DefaultHttpClient");
  if (dhcExists) {
    const targetConstructor = DefaultHttpClient.$init.overload('org.apache.http.params.HttpParams');
    DefaultHttpClient.$init.overload('org.apache.http.conn.ClientConnectionManager', 'org.apache.http.params.HttpParams').implementation = function (_conman, params) {
      return targetConstructor.call(this, params);
    };
  }

  // Apache SSLSocketFactory：$init 后替换内部 sslcontext / socketfactory 字段
  const [ssfExists, SSLSocketFactory] = classExists("org.apache.http.conn.ssl.SSLSocketFactory");
  if (ssfExists) {
    SSLSocketFactory.$init.overload('java.lang.String', 'java.security.KeyStore', 'java.lang.String', 'java.security.KeyStore', 'java.security.SecureRandom', 'org.apache.http.conn.scheme.HostNameResolver').implementation = function (algorithm, keystore, keystorePassword, truststore, random, nameResolver) {
      this.$init(algorithm, keystore, keystorePassword, truststore, random, nameResolver);
      this.sslcontext.value = customSslContext(algorithm);
      this.socketfactory.value = customSslSocketFactory();
    };
    SSLSocketFactory.isSecure.overload('java.net.Socket').implementation = function (_sock) { return true; };
  }

  // Xutils
  const [rpExists, RequestParams] = classExists("org.xutils.http.RequestParams");
  if (rpExists) {
    RequestParams.setSslSocketFactory.implementation = function (_v0) { this.setSslSocketFactory(customSslSocketFactory()); };
    RequestParams.setHostnameVerifier.implementation = function (_v0) { this.setHostnameVerifier(customHostnameVerifier()); };
  }

  // Appcelerator
  const [ptmExists, PinningTrustManager] = classExists("appcelerator.https.PinningTrustManager");
  if (ptmExists) {
    PinningTrustManager.checkServerTrusted.implementation = function () {};
  }

  // ch.boye.httpclientandroidlib
  const [avExists, AbstractVerifier] = classExists("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier");
  if (avExists) {
    AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function (_v0, _v1, _v2, _v3) {};
  }
}

function sslUnpinning() {
  customInit();
  hookJavaStuff();
  hookAndroidStuff();
  hookOkHttp();
  hookConscrypt();
  hookOtherFrameworks();
}

setImmediate(function () {
  if (Java.available) Java.perform(doJavaHook);
});
```

## 3. 双向 TLS 客户端证书导出

Hook `KeyStore$PrivateKeyEntry.getPrivateKey()` 与 `getCertificateChain()`，在应用取出私钥时重新打包 PKCS12。默认密码写在脚本顶部便于修改；输出到 `/sdcard/Download/`（需存储权限）：

```javascript
const password = "Zhang3";

function main() {
    Java.perform(function () {
        const application = Java.use("android.app.Application");
        application.attach.overload("android.content.Context").implementation = function (context) {
            this.attach(context);
            const classLoader = context.getClassLoader();
            const classFactory = Java.ClassFactory.get(classLoader);
            hookKeyStore(classFactory);
        };
        // 无壳可直接 hookKeyStore(Java);
    });
}

const serialNumberSet = new Set();

function exportPkcs12(classFactory, privateKey, certificate, packageName, password) {
    const X509Certificate = classFactory.use("java.security.cert.X509Certificate");
    const certX509 = classFactory.cast(certificate, X509Certificate);
    const serialNumber = certX509.getSerialNumber().toString(16);
    if (!serialNumberSet.has(serialNumber)) {
        const chain = classFactory.array("java.security.cert.X509Certificate", [certX509]);
        const keyStore = classFactory.use("java.security.KeyStore").getInstance("PKCS12", "BC");
        keyStore.load(null, null);
        keyStore.setKeyEntry("client", privateKey, classFactory.use('java.lang.String').$new(password).toCharArray(), chain);
        try {
            const outputPath = `/sdcard/Download/${packageName}.${serialNumber}.p12`;
            const output = classFactory.use("java.io.FileOutputStream").$new(outputPath);
            keyStore.store(output, classFactory.use('java.lang.String').$new(password).toCharArray());
            console.log(`PKCS12 exported to: ${outputPath}`);
            serialNumberSet.add(serialNumber);
        } catch (error) {
            console.error(error);
        }
    }
}

function hookKeyStore(classFactory) {
    classFactory.use("java.security.KeyStore$PrivateKeyEntry").getPrivateKey.implementation = function () {
        const privateKey = this.getPrivateKey();
        const certificate = this.getCertificate();
        const packageName = classFactory.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
        exportPkcs12(classFactory, privateKey, certificate, packageName, password);
        return privateKey;
    };
    classFactory.use("java.security.KeyStore$PrivateKeyEntry").getCertificateChain.implementation = function () {
        const retval = this.getCertificateChain();
        const privateKey = this.getPrivateKey();
        const certificate = this.getCertificate();
        const packageName = classFactory.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
        exportPkcs12(classFactory, privateKey, certificate, packageName, password);
        return retval;
    };
}

setImmediate(main);
```

导出后定位触发者的调用栈：

```javascript
const Log = Java.use('android.util.Log');
const Throwable = Java.use('java.lang.Throwable');
console.log(Log.getStackTraceString(Throwable.$new()));
```

## 4. Socket / TCP / UDP / SSL 全栈流量抓取

开关控制的分层抓包。大部分 HTTPS 场景只开 `hookSsl`；HTTP 明文开 `hookTcp`。native 侧 SSL_read/SSL_write 实现见 `templates-native.md` §13：

```javascript
// hook 开关
const hookSocket = false; // Java层 Socket构造hook
const hookTcp = false;    // TCP hook开关 HTTP的话 开启这个就够了
const hookUdp = false;    // UDP hook开关
const hookConscrypt = false; // 暂时感觉用处不大
const useHexDump = false; // or UTF-8 plaintext
const traceStack = false;

function doJavaHook(classFactory) {
  const Log = classFactory.use("android.util.Log");
  const Throwable = classFactory.use("java.lang.Throwable");
  const Hexdump = classFactory.use("com.android.internal.util.HexDump");
  const String = classFactory.use("java.lang.String");

  const javaBufOpFunc = function (bytes, offset, length) {
    let result = "\n";
    if (length > 0) {
      result += useHexDump
        ? Hexdump.dumpHexString(bytes, offset, length)
        : String.$new(bytes, offset, length, "UTF-8");
    }
    return result;
  };

  if (hookSocket) {
    // 五个构造重载最终都调用这一个，hook 一个即可
    const Socket = classFactory.use("java.net.Socket");
    Socket.$init.overload("[Ljava.net.InetAddress;", "int", "java.net.SocketAddress", "boolean").implementation = function (addresses, port, localAddr, stream) {
      console.log(`\n[*] Socket $init called with\n- port: ${port}\n- stream: ${stream}`);
      if (traceStack) console.log("\t" + Log.getStackTraceString(Throwable.$new()));
      return this.$init(addresses, port, localAddr, stream);
    };
  }

  if (hookTcp) {
    // TCP 收发（native 私有方法 无重载）
    const SocketInputStream = classFactory.use("java.net.SocketInputStream");
    const SocketOutputStream = classFactory.use("java.net.SocketOutputStream");

    SocketOutputStream.socketWrite0.implementation = function (fd, buffer, offset, length) {
      console.log(`\n[*] socketWrite0\n- buffer: ${javaBufOpFunc(buffer, offset, length)}`);
      if (traceStack) console.log("\t" + Log.getStackTraceString(Throwable.$new()));
      return this.socketWrite0(fd, buffer, offset, length);
    };

    SocketInputStream.socketRead0.implementation = function (fd, buffer, offset, length, timeout) {
      const retval = this.socketRead0(fd, buffer, offset, length, timeout);
      console.log(`\n[*] socketRead0\n- buffer: ${javaBufOpFunc(buffer, offset, length)}`);
      if (traceStack) console.log("\t" + Log.getStackTraceString(Throwable.$new()));
      return retval;
    };
  }

  if (hookUdp) {
    const Linux = classFactory.use("libcore.io.Linux");
    Linux.sendtoBytes.overload("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.InetAddress", "int").implementation = function (fd, buffer, offset, length, flags, inetAddress, port) {
      const bytes = classFactory.array("byte", buffer);
      console.log(`\n[*] sendtoBytes\n- buffer: ${javaBufOpFunc(bytes, offset, length)}\n- port: ${port}`);
      return this.sendtoBytes(fd, buffer, offset, length, flags, inetAddress, port);
    };
    Linux.recvfromBytes.implementation = function (fd, buffer, offset, length, flags, srcAddress) {
      const bytes = classFactory.array("byte", buffer);
      console.log(`\n[*] recvfromBytes\n- buffer: ${javaBufOpFunc(bytes, offset, length)}\n- address: ${srcAddress}`);
      return this.recvfromBytes(fd, buffer, offset, length, flags, srcAddress);
    };
  }

  if (hookConscrypt) {
    const NativeCrypto = Java.use("com.android.org.conscrypt.NativeCrypto");
    NativeCrypto.SSL_write.implementation = function (ssl, ssl_holder, fd, shc, buffer, offset, length, writeTimeoutMillis) {
      console.log(`\n[*] NativeCrypto SSL_write\n- buffer: ${javaBufOpFunc(buffer, offset, length)}`);
      return this.SSL_write(ssl, ssl_holder, fd, shc, buffer, offset, length, writeTimeoutMillis);
    };
    NativeCrypto.SSL_read.implementation = function (ssl, ssl_holder, fd, shc, buffer, offset, length, readTimeoutMillis) {
      const retval = this.SSL_read(ssl, ssl_holder, fd, shc, buffer, offset, length, readTimeoutMillis);
      console.log(`\n[*] NativeCrypto SSL_read\n- buffer: ${javaBufOpFunc(buffer, offset, length)}`);
      return retval;
    };
  }
}
```

## 5. OkHttp 流量记录（Interceptor 注入）

读请求和响应 body 前先克隆 `okio.Buffer`，避免消耗业务流；gzip 响应先解压再打印：

```javascript
Java.perform(function () {
    var Buffer = Java.use('okio.Buffer');
    var GzipSource = Java.use('okio.GzipSource');
    var Long = Java.use('java.lang.Long');
    var Interceptor = Java.use('okhttp3.Interceptor');
    var Builder = Java.use('okhttp3.OkHttpClient$Builder');
    var SystemClass = Java.use('java.lang.System');
    var installedBuilders = {};

    function isTextContent(contentType) {
        if (contentType === null) return true;
        var value = contentType.toString().toLowerCase();
        return value.indexOf('text') !== -1 || value.indexOf('json') !== -1 ||
            value.indexOf('xml') !== -1 || value.indexOf('form') !== -1;
    }

    function readBufferUtf8(buffer, gzip) {
        var clone = Java.cast(buffer.clone(), Buffer);
        if (!gzip) return clone.readUtf8();
        var gzipSource = GzipSource.$new(clone);
        var out = Buffer.$new();
        while (gzipSource.read(out, 8192) !== -1) {}
        gzipSource.close();
        return out.readUtf8();
    }

    var LoggingInterceptor = Java.registerClass({
        name: 'org.example.NetworkObserver',
        implements: [Interceptor],
        methods: {
            intercept: [{
                returnType: 'okhttp3.Response',
                argumentTypes: ['okhttp3.Interceptor$Chain'],
                implementation: function (chain) {
                    var request = chain.request();
                    console.log('okhttp request method=' + request.method() + ' url=' + request.url());
                    var requestBody = request.body();
                    // isDuplex / isOneShot 的 body 不要强读
                    if (requestBody !== null && !requestBody.isDuplex() && !requestBody.isOneShot()) {
                        var requestBuffer = Buffer.$new();
                        requestBody.writeTo(requestBuffer);
                        var requestType = requestBody.contentType();
                        if (isTextContent(requestType)) {
                            console.log('okhttp request body=' + readBufferUtf8(requestBuffer, false));
                        } else {
                            console.log('okhttp request body binary length=' + requestBuffer.size());
                        }
                    }

                    var response = chain.proceed(request);
                    var responseBody = response.body();
                    if (responseBody !== null) {
                        var source = responseBody.source();
                        source.request(Long.MAX_VALUE.value);
                        var responseBuffer = Java.cast(source.buffer().clone(), Buffer);
                        var responseType = responseBody.contentType();
                        var gzip = String(response.header('Content-Encoding')).toLowerCase() === 'gzip';
                        if (isTextContent(responseType)) {
                            console.log('okhttp response code=' + response.code() + ' body=' + readBufferUtf8(responseBuffer, gzip));
                        } else {
                            console.log('okhttp response code=' + response.code() + ' binary length=' + responseBuffer.size());
                        }
                    }
                    // 必须返回原始 response，否则业务读不到 body
                    return response;
                }
            }]
        }
    });

    var build = Builder.build.overload();
    build.implementation = function () {
        var builderId = String(SystemClass.identityHashCode(this));
        if (installedBuilders[builderId] !== true) {
            installedBuilders[builderId] = true;
            this.addInterceptor(LoggingInterceptor.$new());
        }
        return build.call(this);
    };
});
```

## 6. 硬件密钥证明（Key Attestation）处理

目标类可能未加载且在 GMS 混淆包中（`com.google.android.gms.org.conscrypt.OpenSSLX509Certificate`）。两层 hook：先用 `ClassLoader.loadClass` 探测目标类加载时机，再安装实际 hook：

```javascript
// 全局搜索、加载目标类（跨 ClassLoader）
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
        console.log(`getExtensionValue(str) called\n- str: ${str}`);
        // attestation 扩展 OID 1.3.6.1.4.1.11129.2.1.17 的篡改不通用，需按具体结构分析
        return retval;
    };
}

// hook时机：等目标类被加载后再 hook
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
```
