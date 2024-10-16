let classFactory = null;
// 如果OkHttp被混淆了 需要手动反编译找到混淆后的包名
// 可以通过手动搜索关键字查找 如
// OkHttpClient CertificatePinner
// const okHttpPackageName = "nl";
const okHttpPackageName = "okhttp3";

let customArrayList = null;
let customTrustManager = null;
let customTrustManagers = null;
let customSslSocketFactory = null;
let customHostnameVerifier = null;
let customSslContext = null;

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
				this.init(km, customTrustManagers(), random);
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

setImmediate(main);
