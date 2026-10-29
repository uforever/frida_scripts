const targetLib = "libflutter.so";

// 0x846110 dart::bin::SSLCertContext::CertificateCallback  -> 1
// 0x706AAC bssl::ssl_verify_peer_cert                      -> 0
// 0x716C00 bssl::ssl_crypto_x509_session_verify_cert_chain -> 1
function disableTLSValidation() {
  const flutterLib = Process.getModuleByName("libflutter.so");
  const flutterBase = flutterLib.base;

  // 这个暂未生效
  // Interceptor.attach(flutterBase.add(0x706AAC), {
  //   onLeave: function (retval) {
  //     retval.replace(0);
  //   }
  // });

  // 下面2个函数随便hook一个
  Interceptor.attach(flutterBase.add(0x846110), {
    onLeave: function (retval) {
      retval.replace(1);
    }
  });

  // Interceptor.attach(flutterBase.add(0x716C00), {
  //   onLeave: function (retval) {
  //     retval.replace(1);
  //   }
  // });

  console.log("[+] flutter TLS validation disabled");
}

function main() {
  Interceptor.attach(Process.getModuleByName("libdl.so").getExportByName("android_dlopen_ext"),
    {
      onEnter: function (args) {
        const pathptr = args[0];
        this.isTarget = false;
        if (pathptr) {
          const path = ptr(pathptr).readCString();
          if (path.includes(targetLib)) {
            this.isTarget = true;
          }
        }
      },
      onLeave: function (_retval) {
        if (this.isTarget) {
          disableTLSValidation();
        }
      }
    });
}

setImmediate(main);


// `https://github.com/dart-lang/sdk/blob/main/runtime/bin/security_context.cc`
// 检索 "CertificateCallback called with no current isolate" 字符串引用
// 定位到函数 CertificateCallback 改为返回 1

// IDA 中使用 Search -> Sequence of bytes 进行全局搜索以下序列
// F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9
// F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9
// FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9
// 定位到函数 ssl_verify_peer_cert 改为返回 0
// FF ?3 01 D1 F? ?? 01 A9 ?? ?? ?? 94 ?? ?? ?? 52 48 00 00 39 1A 50 40 F9 DA 02 00 B4 48 03 40 F9
// 定位到函数 ssl_crypto_x509_session_verify_cert_chain 改为返回 1

// 搜索字符串 android_arm64 找到dart版本 如 3.9.0 (stable)
// 找到对应的flutter版本 如 3.35.0 3.35.1 3.35.2
// GitHub上找到对应的hash 如 1e9a811bf8e70466596bcf0ea3a8b5adb5f17f7f
// `https://github.com/flutter/flutter/blob/3.35.0/bin/internal/engine.version`
// `https://github.com/flutter/flutter/blob/3.47.8/bin/internal/engine.version`
// 下载动态库
// `https://storage.googleapis.com/flutter_infra_release/flutter/1e9a811bf8e70466596bcf0ea3a8b5adb5f17f7f/android-arm64-release/symbols.zip`
// 找到 CertificateCallback ssl_verify_peer_cert ssl_crypto_x509_session_verify_cert_chain 函数的字节码 直接搜索

// 或者 通过 IDA Diaphora 插件 先建立有符号版本的SQLite数据库 然后在无符号版本中进行函数匹配
// 为目标函数添加注释 使用`;`键 加快导出速度
// 选中"Export only non-IDA generated functions"和"Do not export instructions and basic blocks"
// 取消勾选"Use the decompiler if available"

// 或者 通过 Binary Ninja 签名库功能
// 先打开带符号的动态库 选中目标函数
// 运行命令 > WARP Include Function
// 三个都选中 运行 > WARP Process 选中当前so文件
// 分别选 All Selected 然后保存到文件中
// 再打开裁剪后的动态库 运行 > WARP Load File
// 然后直接搜索函数名就可以定位到目标函数的偏移 可能需要rebase
