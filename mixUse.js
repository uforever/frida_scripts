const targetLib = "libmsaoaidsec.so";
let alreadyHook = false;
let classFactory = null;

const okHttpPackageName = "okhttp3";
const searchedPackages = new Set();

let customArrayList = null;
let customTrustManager = null;
let customTrustManagers = null;
let customSslSocketFactory = null;
let customHostnameVerifier = null;
let customSslContext = null;

function main() {
  const adeAddr = Module.findExportByName(null, "android_dlopen_ext");
  Interceptor.attach(adeAddr, {
    onEnter: function (args) {
      const pathptr = args[0];
      if (pathptr) {
        const path = ptr(pathptr).readCString();
        // 分析前先打开
        // console.log("[dylib open]: ", path);

        if (path.includes(targetLib)) {
          this.isTarget = true;
          hook_init_proc();
        }
      }
    },
    onLeave: function () {
      if (this.isTarget) {
        const jniOnload = Module.findExportByName(targetLib, "JNI_OnLoad");
        console.log("[hit JNI_OnLoad]: " + jniOnload);
        // 如果有输出的话 说明检测点在JNI_OnLoad之中或者之后
        // 否则可能在.init_proc .init_array .init_xxx等函数中
        Interceptor.attach(jniOnload, {
          onEnter: function (_args) {
            // 其中有检测是否有java层hook
            // hook后 & 0x80000 != 0
            console.log("[func invoke]: JNI_OnLoad");
          },
          onLeave: function () {
            if (Java.available) {
              Java.perform(doJavaHook);
            }
          },
        });
      }
    },
  });
}

function doJavaHook() {
  const Application = Java.use("android.app.Application");
  Application.attach.overload("android.content.Context").implementation = function (context) {
    this.attach(context);
    const classLoader = context.getClassLoader();
    classFactory = Java.ClassFactory.get(classLoader);
  };
  if (classFactory) {
    console.log("[with shell]");
  } else {
    classFactory = Java;
    console.log("[without shell]");
  }
  sslUnpinning();
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

  // 获取函数hook之前的前8个字节
  // const xxxPtr = Module.findExportByName("libc.so", "xxx");
  // console.log(`access first 8 bytes before hook: ${hexdump(xxxPtr, {
  //   offset: 0,
  //   length: 8,
  //   header: true,
  //   ansi: true
  // })}`);

  // 分析前先注释掉这里
  nop(baseAddr, 0x1C544);
  nop(baseAddr, 0x1B8D4);
  nop(baseAddr, 0x26E5C);

  generalBypassHook();

  // 分析前先打开这里 注释掉上面
  // hook pthread_create 函数
  // Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
  //   onEnter(args) {
  //     const threadFuncAddr = args[2];
  //     console.log("The thread function address is " + ptr(threadFuncAddr).sub(baseAddr));
  //   }
  // });

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
    console.log(`thread func sub_${offset.toString(16).toUpperCase()} noped`)
  }, 'void', []));
}

function generalBypassHook() {
  // hook fgets 函数
  const fgetsPtr = Module.findExportByName("libc.so", 'fgets');
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
  const strstrPtr = Module.findExportByName("libc.so", 'strstr');
  Interceptor.attach(strstrPtr, {
    onEnter: function (args) {
      const keyWord = args[1].readCString();
      if (
        keyWord.includes("frida") ||
        keyWord.includes(":69A2") ||
        keyWord.includes("gum-js") ||
        keyWord.includes("REJECT") ||
        keyWord.includes("gmain") ||
        keyWord.includes("gdbus") ||
        keyWord.includes("linjector")
      ) {
        this.isCheck = true;
      }
    },
    onLeave: function (retval) {
      if (this.isCheck) {
        retval.replace(0);
      }
    }
  });

  // hook access 函数
  const accessPtr = Module.findExportByName("libc.so", 'access');
  Interceptor.attach(accessPtr, {
    onEnter: function (args) {
      const path = args[0].readCString();
      if (
        path.includes("re.frida.server") ||
        path.includes("/data/local/tmp")
      ) {
        this.isCheck = true;
      }
    },
    onLeave: function (retval) {
      if (this.isCheck) {
        retval.replace(-1);
      }
    },
  });
}

setImmediate(main);

function sslUnpinning() {
  customInit();

  hookJavaStuff();
  hookAndroidStuff();
  hookOkHttp();
  hookConscrypt();
  hookApacheHttp();
  hookAppcelerator();
  hookXutils();
  hookChBoye();
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
    // hook 其中 checkServerTrusted 和 checkTrusted 方法
    const ArrayList = classFactory.use('java.util.ArrayList');
    customArrayList = function () {
      return ArrayList.$new();
    };


    // 准备两个自定义参数 customTrustManager 和 customSslSocketFactory
    const X509TrustManager = classFactory.use('javax.net.ssl.X509TrustManager');
    // 创建了一个自定义的类 CustomTrustManager 覆盖 SSL/TLS 证书的验证逻辑 
    const CustomTrustManager = classFactory.registerClass({
      name: "CustomTrustManager",
      implements: [X509TrustManager],
      methods: {
        // 当客户端证书被检查时调用，什么都不做，仅打印日志。
        checkClientTrusted(_chain, _authType) {
          console.log("CustomTrustManager check client trusted called");
        },
        // 当服务器证书被检查时调用，同样什么都不做，仅打印日志。
        checkServerTrusted(_chain, _authType) {
          console.log("CustomTrustManager check server trusted called");
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

    customTrustManagers = function () {
      return classFactory.array("Ljavax.net.ssl.X509TrustManager;", [customTrustManager()]);
    };

    // 使用 SSLContext 创建一个 TLS 上下文
    const SSLContext = classFactory.use("javax.net.ssl.SSLContext");
    customSslContext = function (algorithm) {
      return SSLContext.getInstance(algorithm);
    };

    const tlsInstance = customSslContext("TLS");
    // 将刚才创建的 TrustAllManager 作为信任管理器进行初始化
    tlsInstance.init(null, customTrustManagers(), null);
    // 获取 SSLSocketFactory，允许创建 SSL 套接字
    customSslSocketFactory = function () {
      return tlsInstance.getSocketFactory();
    };

    try {
      SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (km, _tm, random) {
        console.log("javax.net.ssl.SSLContext.init('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom') called");
        // this.init(km, customTrustManagers(), random);
        this.init(null, customTrustManagers(), null);
      }
    } catch (err) {
      console.error(err.message);
    }

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

  } catch (err) {
    console.error(err.message);
  }
}

function hookJavaStuff() {
  const targetTMF = "javax.net.ssl.TrustManagerFactory";
  const [TrustManagerFactoryExists, TrustManagerFactory] = classExists(targetTMF);
  if (TrustManagerFactoryExists) {
    try {
      TrustManagerFactory.getTrustManagers.overload().implementation = function () {
        console.log("javax.net.ssl.TrustManagerFactory.getTrustManagers() called");
        return customTrustManagers();
      };
    } catch (err) {
      console.error(err.message);
    }
  }

  const targetHUC = "javax.net.ssl.HttpsURLConnection";
  const [HttpsURLConnectionExists, HttpsURLConnection] = classExists(targetHUC);
  if (HttpsURLConnectionExists) {
    try {
      HttpsURLConnection.setDefaultHostnameVerifier.overload('javax.net.ssl.HostnameVerifier').implementation = function (_v) {
        console.log("javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier('javax.net.ssl.HostnameVerifier') called");
      };
      HttpsURLConnection.setHostnameVerifier.overload('javax.net.ssl.HostnameVerifier').implementation = function (_v) {
        console.log("javax.net.ssl.HttpsURLConnection.setHostnameVerifier('javax.net.ssl.HostnameVerifier') called");
      };
      HttpsURLConnection.setSSLSocketFactory.overload('javax.net.ssl.SSLSocketFactory').implementation = function (_sf) {
        console.log("javax.net.ssl.HttpsURLConnection.setSSLSocketFactory('javax.net.ssl.SSLSocketFactory') called");
      };
    } catch (err) {
      console.error(err.message);
    }
  }
}

function hookAndroidStuff() {
  // 安卓本身自带的公钥固定的方法也需要hook
  const targetNSTM = "android.security.net.config.NetworkSecurityTrustManager";
  const [NetworkSecurityTrustManagerExists, NetworkSecurityTrustManager] = classExists(targetNSTM);
  if (NetworkSecurityTrustManagerExists) {
    NetworkSecurityTrustManager.checkPins.implementation = function () {
      console.log("android.security.net.config.NetworkSecurityTrustManager.checkPins('[Ljava.security.cert.X509Certificate;') called");
    };
  }

  const targetXTME = "android.net.http.X509TrustManagerExtensions";
  const [X509TrustManagerExtensionsExists, X509TrustManagerExtensions] = classExists(targetXTME);
  if (X509TrustManagerExtensionsExists) {
    X509TrustManagerExtensions.checkServerTrusted.implementation = function (_chain, _authType, _host) {
      console.log("android.net.http.X509TrustManagerExtensions.checkServerTrusted('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String') called");
      return customArrayList();
    };
  }

  const targetWVC = "android.webkit.WebViewClient";
  const [WebViewClientExists, WebViewClient] = classExists(targetWVC);
  if (WebViewClientExists) {
    WebViewClient.onReceivedSslError.implementation = function (_view, handler, _error) {
      console.log(classFactory.use("java.lang.Throwable").$new().getStackTrace());
      handler.proceed();
    };
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

    // okhttp3.CertificatePinner 的 check 方法
    // okhttp3.internal.tls.OkHostnameVerifier 的 verify 方法
  }
}

function hookConscrypt() {
  const targetTMI = "com.android.org.conscrypt.TrustManagerImpl";
  const [TrustManagerImplExists, TrustManagerImpl] = classExists(targetTMI);
  if (TrustManagerImplExists) {
    try {
      TrustManagerImpl.checkTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'javax.net.ssl.SSLSession', 'javax.net.ssl.SSLParameters', 'boolean').implementation = function (_v0, _v1, _v2, _v3, _v4) {
        console.log("com.android.org.conscrypt.TrustManagerImpl.checkTrusted('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'javax.net.ssl.SSLSession', 'javax.net.ssl.SSLParameters', 'boolean') called");
        return customArrayList();
      };
    } catch (err) {
      console.error(err.message);
    }

    try {
      TrustManagerImpl.checkTrusted.overload('[Ljava.security.cert.X509Certificate;', '[B', '[B', 'java.lang.String', 'java.lang.String', 'boolean').implementation = function (_v0, _v1, _v2, _v3, _v4, _v5) {
        console.log("com.android.org.conscrypt.TrustManagerImpl.checkTrusted('[Ljava.security.cert.X509Certificate;', '[B', '[B', 'java.lang.String', 'java.lang.String', 'boolean') called");
        return customArrayList();
      };
    } catch (err) {
      console.error(err.message);
    }
  }

  const targetCP = "com.android.org.conscrypt.Platform";
  const [PlatformExists, Platform] = classExists(targetCP);
  if (PlatformExists) {
    try {
      Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.AbstractConscryptSocket').implementation = function (_v0, _v1, _v2, _v3) {
        console.log("com.android.org.conscrypt.Platform.checkServerTrusted(javax.net.ssl.X509TrustManager,java.security.cert.X509Certificate[],java.lang.String,com.android.org.conscrypt.AbstractConscryptSocket) called");
      };
    } catch (err) {
      console.error(err.message);
    }

    try {
      Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.ConscryptEngine').implementation = function (_v0, _v1, _v2, _v3) {
        console.log("com.android.org.conscrypt.Platform.checkServerTrusted(javax.net.ssl.X509TrustManager,java.security.cert.X509Certificate[],java.lang.String,com.android.org.conscrypt.ConscryptEngine) called");
      };
    } catch (err) {
      console.error(err.message);
    }
  }

  const targetOSSFI = "com.android.org.conscrypt.OpenSSLSocketFactoryImpl";
  const [OpenSSLSocketFactoryImplExists, OpenSSLSocketFactoryImpl] = classExists(targetOSSFI);
  if (OpenSSLSocketFactoryImplExists) {
    const createSocketOverloads = OpenSSLSocketFactoryImpl.createSocket.overloads;
    const Modifier = classFactory.use("java.lang.reflect.Modifier");
    for (const createSocket of createSocketOverloads) {
      createSocket.implementation = function () {
        console.log(`com.android.org.conscrypt.OpenSSLSocketFactoryImpl.createSocket(${createSocket.argumentTypes}) called`);
        // console.log(classFactory.use("java.lang.Throwable").$new().getStackTrace());
        const stackTraceElements = classFactory.use("java.lang.Throwable").$new().getStackTrace();
        for (const stElement of stackTraceElements) {
          const stElementClassName = stElement.getClassName();

          if (searchedPackages.has(stElementClassName)) {
            continue;
          }
          searchedPackages.add(stElementClassName);

          const stElementClass = classFactory.use(stElementClassName);
          if (stElementClass.class.getSuperclass().getName() === "java.lang.Object") {
            continue;
          }

          const stElementClassFields = stElementClass.class.getDeclaredFields();

          let fieldsFinalListCount = 0;
          let fieldsSocketCount = 0;
          let fieldsIntCount = 0;
          let fieldsBooleanCount = 0;
          let fieldsLongCount = 0;

          for (const stElementClassField of stElementClassFields) {
            // console.log(stElementClassField.getName());
            const stElementClassFieldModifiers = stElementClassField.getModifiers();
            const stElementClassFieldIsStatic = Modifier.isStatic(stElementClassFieldModifiers);
            if (stElementClassFieldIsStatic) {
              continue;
            }
            const stElementClassFieldType = stElementClassField.getType().getName();
            const stElementClassFieldIsFinal = Modifier.isFinal(stElementClassFieldModifiers);
            if (stElementClassFieldIsFinal) {
              if (stElementClassFieldType === "java.util.List") {
                fieldsFinalListCount++;
              } else {
                continue;
              }
            }

            if (stElementClassFieldType === "java.net.Socket") {
              fieldsSocketCount++;
            } else if (stElementClassFieldType === "int") {
              fieldsIntCount++;
            } else if (stElementClassFieldType === "boolean") {
              fieldsBooleanCount++;
            } else if (stElementClassFieldType === "long") {
              fieldsLongCount++;
            }
          }

          if (fieldsFinalListCount != 1) {
            continue;
          }

          if (fieldsSocketCount != 2) {
            continue;
          }

          if (fieldsBooleanCount != 1) {
            continue;
          }

          if (fieldsLongCount != 1) {
            continue;
          }

          if (fieldsIntCount != 2 && fieldsIntCount != 4) {
            continue;
          }

          const stElementClassConstructors = stElementClass.class.getDeclaredConstructors();
          if (stElementClassConstructors.length != 1) {
            continue;
          }

          const stElementClassConstructor = stElementClassConstructors[0];
          const stElementClassConstructorParameterTypes = stElementClassConstructor.getParameterTypes();
          if (stElementClassConstructorParameterTypes.length != 2) {
            continue;
          }

          // 可能是 okhttp 中的 RealConnection 类
          const classRealConnection = stElementClassName;
          console.log("[class find] maybe okhttp RealConnection: ", classRealConnection);

          // 可能是 okhttp 中的 Route 类
          const classRoute = stElementClassConstructorParameterTypes[1].getName();
          console.log("[class find] maybe okhttp Route: ", classRoute);
          const classRouteConstructors = classFactory.use(classRoute).class.getDeclaredConstructors();
          if (classRouteConstructors.length != 1) {
            continue;
          }
          const classRouteConstructor = classRouteConstructors[0];
          const classRouteConstructorParameterTypes = classRouteConstructor.getParameterTypes();
          if (classRouteConstructorParameterTypes.length != 3) {
            continue;
          }

          // 可能是 okhttp 中的 Address 类
          const classAddress = classRouteConstructorParameterTypes[0].getName();
          console.log("[class find] maybe okhttp Address: ", classAddress);
          const Address = classFactory.use(classAddress);
          const classAddressConstructors = Address.class.getDeclaredConstructors();
          if (classAddressConstructors.length != 1) {
            continue;
          }
          const classAddressConstructor = classAddressConstructors[0];
          const classAddressConstructorParameterTypes = classAddressConstructor.getParameterTypes();
          if (classAddressConstructorParameterTypes.length != 12) {
            continue;
          }

          Address.$init.implementation = function (
            uriHost, uriPort, dns, socketFactory, sslSocketFactory,
            hostnameVerifier, certificatePinner, authenticator,
            proxy, protocols, connectionSpecs, proxySelector
          ) {
            const classHostnameVerifier = classAddressConstructorParameterTypes[5].getName();
            if (classHostnameVerifier !== "javax.net.ssl.HostnameVerifier") {
              console.log("[class find] maybe HostnameVerifier: ", classHostnameVerifier);
            }
            // TODO: hook HostnameVerifier

            return this.$init(
              uriHost, uriPort, dns, socketFactory, sslSocketFactory,
              hostnameVerifier, certificatePinner, authenticator,
              proxy, protocols, connectionSpecs, proxySelector
            );
          };

          // 可能是 okhttp 中的 CertificatePinner 类
          const classCertificatePinner = classAddressConstructorParameterTypes[6].getName();
          console.log("[class find] maybe okhttp CertificatePinner: ", classCertificatePinner);
          const CertificatePinner = classFactory.use(classCertificatePinner);
          const classCertificatePinnerMethods = CertificatePinner.class.getDeclaredMethods();
          for (const classCertificatePinnerMethod of classCertificatePinnerMethods) {
            const methodReturnType = classCertificatePinnerMethod.getReturnType().getName();
            if (methodReturnType !== "void") {
              continue;
            }
            const methodParameterTypes = classCertificatePinnerMethod.getParameterTypes();
            if (methodParameterTypes.length != 2) {
              continue;
            }
            const methodParameterType0 = methodParameterTypes[0].getName();
            const methodParameterType1 = methodParameterTypes[1].getName();
            if (methodParameterType0 !== "java.lang.String") {
              continue;
            }
            if (methodParameterType1 !== "java.util.List") {
              continue;
            }
            const checkMethod = classCertificatePinnerMethod.getName();
            console.log("[class find] maybe okhttp CertificatePinner check method: ", checkMethod);
            // hook CertificatePinner check method
            CertificatePinner[checkMethod].overload('java.lang.String', 'java.util.List').implementation = function (_hostname, _certificates) {
              console.log("okhttp CertificatePinner check('java.lang.String', 'java.util.List') called");
            };
          }
        }
        return createSocket.apply(this, arguments);
      }
    }
  }
}

function hookApacheHttp() {
  const targetDHC = "org.apache.http.impl.client.DefaultHttpClient";
  const [DefaultHttpClientExists, DefaultHttpClient] = classExists(targetDHC);
  if (DefaultHttpClientExists) {
    try {
      const targetConstructor = DefaultHttpClient.$init.overload('org.apache.http.params.HttpParams');
      DefaultHttpClient.$init.overload('org.apache.http.conn.ClientConnectionManager', 'org.apache.http.params.HttpParams').implementation = function (_conman, params) {
        const retval = targetConstructor.call(this, params);
        console.log("org.apache.http.impl.client.DefaultHttpClient.$init('org.apache.http.conn.ClientConnectionManager', 'org.apache.http.params.HttpParams') called");
        return retval;
      };
    } catch (err) {
      console.error(err.message);
    }
  }

  const targetSSF = "org.apache.http.conn.ssl.SSLSocketFactory";
  const [SSLSocketFactoryExists, SSLSocketFactory] = classExists(targetSSF);
  if (SSLSocketFactoryExists) {
    try {
      SSLSocketFactory.$init.overload('java.lang.String', 'java.security.KeyStore', 'java.lang.String', 'java.security.KeyStore', 'java.security.SecureRandom', 'org.apache.http.conn.scheme.HostNameResolver').implementation = function (algorithm, keystore, keystorePassword, truststore, random, nameResolver) {
        this.$init(algorithm, keystore, keystorePassword, truststore, random, nameResolver);
        console.log("org.apache.http.conn.ssl.SSLSocketFactory.$init('java.lang.String', 'java.security.KeyStore', 'java.lang.String', 'java.security.KeyStore', 'java.security.SecureRandom', 'org.apache.http.conn.scheme.HostNameResolver') called");

        this.sslcontext.value = customSslContext(algorithm);
        this.socketfactory.value = customSslSocketFactory();
      };
    } catch (err) {
      console.error(err.message);
    }

    try {
      SSLSocketFactory.getSocketFactory.overload().implementation = function () {
        console.log("org.apache.http.conn.ssl.SSLSocketFactory.getSocketFactory() called");
        return SSLSocketFactory.$new();
      };
    } catch (err) {
      console.error(err.message);
    }

    try {
      SSLSocketFactory.isSecure.overload('java.net.Socket').implementation = function (_sock) {
        console.log("org.apache.http.conn.ssl.SSLSocketFactory.isSecure('java.net.Socket') called");
        return true;
      };
    } catch (err) {
      console.error(err.message);
    }
  }
}

function hookAppcelerator() {
  const targetPTM = "appcelerator.https.PinningTrustManager";
  const [PinningTrustManagerExists, PinningTrustManager] = classExists(targetPTM);
  if (PinningTrustManagerExists) {
    try {
      PinningTrustManager.checkServerTrusted.implementation = function () {
        console.log("appcelerator.https.PinningTrustManager.checkServerTrusted('[Ljava.security.cert.X509Certificate;', 'java.lang.String') called");
      }
    } catch (err) {
      console.error(err.message);
    }
  }
}

function hookXutils() {
  const targetRP = "org.xutils.http.RequestParams";
  const [RequestParamsExists, RequestParams] = classExists(targetRP);
  if (RequestParamsExists) {
    try {
      // 对 setSslSocketFactory 和 setHostnameVerifier 两个方法进行hook
      RequestParams.setSslSocketFactory.implementation = function (_v0) {
        console.log("org.xutils.http.RequestParams.setSslSocketFactory('javax.net.ssl.SSLSocketFactory') called");
        this.setSslSocketFactory(customSslSocketFactory());
      };

      RequestParams.setHostnameVerifier.implementation = function (_v0) {
        console.log("org.xutils.http.RequestParams.setHostnameVerifier('javax.net.ssl.HostnameVerifier') called");
        this.setHostnameVerifier(customHostnameVerifier());
      };
    } catch (err) {
      console.error(err.message);
    }
  }
}

function hookChBoye() {
  const targetAV = "ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier";
  const [AbstractVerifierExists, AbstractVerifier] = classExists(targetAV);
  if (AbstractVerifierExists) {
    try {
      AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function (_v0, _v1, _v2, _v3) {
        console.log("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier.verify('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean') called");
      };
    } catch (err) {
      console.error(err.message);
    }
  }
}
