# Java 层模板

所有代码可直接运行（Frida 17 API）。

## 1. 基础 hook 全模式

覆盖静态字段、实例字段、静态/实例/构造方法、内部类、批量 hook、动态加载类：

```javascript
Java.perform(() => {
    // target class
    const FridaActivity1 = Java.use("com.example.androiddemo.Activity.FridaActivity1");
    // inner class 用 $ 连接
    const FridaActivity4_InnerClasses = Java.use("com.example.androiddemo.Activity.FridaActivity4$InnerClasses");

    // hook 静态字段
    FridaActivity1.static_bool_var.value = true;

    // 实例初始化时进行 Hook，并调用实例方法
    const FridaActivity2 = Java.use("com.example.androiddemo.Activity.FridaActivity2");
    FridaActivity2.$init.overload().implementation = function () {
        this.$init();
        this.setBool_var();          // 调用 non-static 方法
    };

    // hook 实例字段；存在同名方法与字段时，字段加 _ 前缀
    const FridaActivity3 = Java.use("com.example.androiddemo.Activity.FridaActivity3");
    FridaActivity3.$init.overload().implementation = function () {
        this.$init();
        this.bool_var.value = true;
        this._same_name_bool_var.value = true;
    };

    // 调用静态方法
    FridaActivity2.setStatic_bool_var();

    // hook 静态方法
    FridaActivity1.a.implementation = function (bArr) {
        return "R4jSLLLLLLLLLLOrLE7/5B+Z6fsl65yj6BgC6YWz66gO6g2t65Pk6a+P65NK44NNROl0wNOLLLL=";
    };

    // 批量 hook：按方法名前缀 hook 类的全部匹配方法
    const methods = FridaActivity4_InnerClasses.class.getDeclaredMethods();
    for (const method of methods) {
        const methodName = method.getName();
        if (methodName.startsWith("check")) {
            FridaActivity4_InnerClasses[methodName].implementation = function () {
                return true;
            }
        }
    }

    // hook 动态加载的内容：枚举全部 ClassLoader 找到目标类
    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            try {
                if (loader.findClass("com.example.androiddemo.Dynamic.DynamicCheck")) {
                    // 也可修改默认 factory：Java.classFactory.loader = loader;
                    const classFactory = Java.ClassFactory.get(loader);
                    const DynamicCheck = classFactory.use("com.example.androiddemo.Dynamic.DynamicCheck");
                    DynamicCheck.check.implementation = function () {
                        return true;
                    };
                }
            } catch (e) { }
        },
        onComplete: function () { }   // 必须加，否则报错
    });

    // 批量 hook 已加载的匹配类
    Java.enumerateLoadedClasses({
        onMatch: function (name, _handle) {
            if (name.includes("com.example.androiddemo.Activity.Frida6.Frida6Class")) {
                Java.use(name).check.implementation = function () { return true; }
            }
        },
        onComplete: function () { }
    });
});
```

## 2. Java 主动调用

调用实例方法（Java.choose 选实例 / 手动 $new）、构造方法、数组参数：

```javascript
// 提升到全局
let toastPrint = null;

// 方式一：Java.choose 选择已有实例，主线程调度调用实例方法
function invokeInstanceFunc() {
  Java.perform(function () {
    let mainActivity = null;
    Java.choose("com.xiaojianbang.app.MainActivity", {
      onMatch: function (instance) { mainActivity = instance; },
      onComplete: function () { }
    });
    if (mainActivity) {
      toastPrint = function (msg) {
        Java.scheduleOnMainThread(function () {
          mainActivity.toastPrint(msg);
        });
      };
    }
  });
}

// 方式二：手动创建实例（$new 调用构造，$init 用于 hook 构造）
function invokeInstanceFunc2() {
  Java.perform(function () {
    const javaString = Java.use("java.lang.String");
    const innerClass = Java.use("com.xiaojianbang.app.Money$innerClass");
    const innerClassObj = innerClass.$new(javaString.$new("zhang3"), 22333);
    toastPrint(innerClassObj.outPrint());
  });
}

// 构造方法调用
function invokeConstructor() {
  Java.perform(function () {
    const Money = Java.use("com.xiaojianbang.app.Money");
    toastPrint(Money.$new().name());
  });
}

// 数组参数
function withArrayArg() {
  Java.perform(function () {
    const Utils = Java.use("com.xiaojianbang.app.Utils");
    const utilsObj = Utils.$new();
    toastPrint(utilsObj.myPrint(
      Java.array("java.lang.String", ["hello", " :)", "frida"])
    ));
  });
}
```

## 3. 加固壳内定位业务类

壳替换了 ClassLoader，必须用 `Application.attach` 时机获取应用 ClassLoader，再通过 `Java.ClassFactory.get` 创建工厂。`$super` 可调用父类方法：

```javascript
Java.perform(() => {
    var application = Java.use("android.app.Application");
    application.attach.overload("android.content.Context").implementation = function (context) {
        // 执行原来的方法
        this.attach(context);
        var classLoader = context.getClassLoader();
        var classFactory = Java.ClassFactory.get(classLoader);
        var targetClass = classFactory.use("com.example.application.TargetClass");

        targetClass.target.overload().implementation = function () {
            // 父类方法调用
            this.$super.SomeSuperFunc();
        }
    }
});
```

无壳应用可直接 `classFactory = Java` 后用 `Java.use`。

## 4. 批量方法追踪（调用链分析）

按包名白/黑名单批量 hook 全部已加载类的方法，输出参数、调用栈、返回值。注意事项：`enumerateLoadedClasses` 只枚举当前已加载的类，最好等相关功能执行后再 hook；日志量大时用 `frida -U -f <pkg> -l agent.js -o trace.log` 落盘：

```javascript
// 按包名hook: hook("com.example.androiddemo", null);   denyList 为 null 不过滤，"$" 跳过内部类
const allowList = "com.example.androiddemo";
const denyList = "$";
const showCallStack = false;

// hook 单个方法（遍历所有重载）
const hookJavaMethod = function (methodName, targetClass, className) {
  const target = targetClass || Java.use(className);
  const overloads = target[methodName].overloads;
  for (const overload of overloads) {
    overload.implementation = function () {
      const retval = overload.apply(this, arguments);
      const methodSign = overload.toString();
      console.log(`\n-------- ${methodSign.replace("function ", className + ".")} ----------`);
      if (arguments.length > 0) console.log(`[arguments]:`);
      for (const arg of arguments) console.log(`  - ${arg.toString()}`);
      if (showCallStack) {
        const callStack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
        console.log(`[call stack]:\n${callStack}`);
      }
      if (retval !== undefined && retval !== null) console.log(`[return value]:\n${retval.toString()}`);
      return retval;
    };
  }
}

// hook 单个类的全部方法（含构造）
const hookJavaClass = function (className, classFactory) {
  console.log(`\n-------- ${className} ----------`);
  const targetClass = classFactory.use(className);
  const methods = targetClass.class.getDeclaredMethods();
  const constructors = targetClass.class.getDeclaredConstructors();

  const methodNames = new Set(methods.map(m => m.getName()));
  if (constructors.length > 0) {
    methodNames.add("$init");
  }
  for (const methodName of methodNames) hookJavaMethod(methodName, targetClass, className);
}

// 按包名批量：先收集目标类，再遍历全部 ClassLoader 匹配 hook
const hookAndroid = function (allowList, denyList) {
  Java.perform(function () {
    let targetClasses = new Array();
    Java.enumerateLoadedClasses({
      onMatch: function (name, _handle) {
        if (name.includes(allowList) && !name.includes(denyList)) targetClasses.push(name);
      },
      onComplete: function () { }
    });
    console.log(`Found ${targetClasses.length} target classes`);

    Java.enumerateClassLoaders({
      onMatch: function (loader) {
        const classFactory = Java.ClassFactory.get(loader);
        targetClasses = targetClasses.filter(function (name) {
          try {
            if (loader.findClass(name)) {
              hookJavaClass(name, classFactory);
              return false;
            }
          } catch (e) { }
          return true;
        });
      },
      onComplete: function () { },
    });
  });
};

const hook = function (allowList, denyList) {
  if (Java.available) hookAndroid(allowList, denyList);
};

setImmediate(function () {
  // 相关功能触发后再执行，避免类未加载漏 hook；也可在 REPL 中手动执行
  // hook(allowList, denyList);
});
```

## 5. 加密算法自吐

hook `Cipher`/`SecretKeySpec`/`MessageDigest`/`Mac`/`Signature` 等类，输出算法、密钥、输入输出（hex + base64）。开关控制的完整结构：

```javascript
Java.perform(function () {
    // 按需开启
    const MODE = {
        KeyGenerator: true,
        SecretKeySpec: true,
        MessageDigest: true,
        Signature: true,
        Cipher: true,
        Mac: true,
        IvParameterSpec: true,
    };

    const STRING = Java.use("java.lang.String");
    const BASE64 = Java.use("java.util.Base64");

    const bytesToString = (bytes) => bytes === null ? null : STRING.$new(bytes).toString();
    const bytesToBase64 = (bytes) => bytes === null ? null : BASE64.getEncoder().encodeToString(bytes);

    if (MODE.SecretKeySpec) {
        const secretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        secretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, cipher) {
            console.log(`SecretKeySpec.init\n- Key Base64: ${bytesToBase64(key)}\n- Key String: ${bytesToString(key)}\n- Algorithm: ${cipher}`);
            return secretKeySpec.$init.overload("[B", "java.lang.String").call(this, key, cipher);
        }
    }

    if (MODE.MessageDigest) {
        const messageDigest = Java.use("java.security.MessageDigest");
        messageDigest.getInstance.overload("java.lang.String").implementation = function (arg0) {
            console.log(`MessageDigest.getInstance\n- Algorithm: ${arg0}`);
            return this.getInstance(arg0);
        };
        messageDigest.update.overload("[B").implementation = function (input) {
            console.log(`MessageDigest.update\n- input Base64: ${bytesToBase64(input)}`);
            return this.update(input);
        };
    }

    if (MODE.IvParameterSpec) {
        const ivSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        ivSpec.$init.overload("[B").implementation = function (iv) {
            console.log(`IvParameterSpec.init\n- IV Base64: ${bytesToBase64(iv)}`);
            return ivSpec.$init.overload("[B").call(this, iv);
        }
    }

    if (MODE.Cipher) {
        const cipher = Java.use("javax.crypto.Cipher");
        cipher.init.overload("int", "java.security.Key").implementation = function (opmode, key) {
            console.log(`cipher.init\n- Key: ${bytesToBase64(key.getEncoded())}\n- Opmode: ${opmode}\n- Algorithm: ${this.getAlgorithm()}`);
            this.init.overload("int", "java.security.Key").call(this, opmode, key);
        }
        cipher.doFinal.overload('[B').implementation = function (input) {
            console.log(`Cipher.doFinal\n- input: ${bytesToString(input)}\n- input Base64: ${bytesToBase64(input)}`);
            const result = this.doFinal(input);
            console.log(`- result: ${bytesToString(result)}\n- result Base64: ${bytesToBase64(result)}`);
            return result;
        };
    }

    if (MODE.Mac) {
        const mac = Java.use("javax.crypto.Mac");
        mac.getInstance.overload("java.lang.String").implementation = function (arg0) {
            console.log(`Mac.getInstance\n- Algorithm: ${arg0}`);
            return this.getInstance(arg0);
        };
        mac.doFinal.overload('[B').implementation = function (input) {
            const result = this.doFinal(input);
            console.log(`Mac.doFinal\n- Algorithm: ${this.getAlgorithm()}\n- input Base64: ${bytesToBase64(input)}\n- result Base64: ${bytesToBase64(result)}`);
            return result;
        };
    }

    console.log("-------- Start Hooking Java Crypto API --------");
});
```

Hook 点优先级：先 `SecretKeySpec`（密钥）→ `Cipher.init`（算法+IV）→ `Cipher.doFinal`（输入输出）。需要调用栈时打印：

```javascript
const Log = Java.use("android.util.Log");
const Throwable = Java.use("java.lang.Throwable");
console.log(Log.getStackTraceString(Throwable.$new()));
```

## 6. UI 事件监听

追踪 View 点击事件与监听器类名，兼容 spawn 与 attach 两种注入时机：

```javascript
let classFactory = null;

function main() {
  Java.perform(doJavaHook);
}

function doJavaHook() {
  const Application = Java.use("android.app.Application");
  Application.attach.overload("android.content.Context").implementation = function (context) {
    this.attach(context);
    const classLoader = context.getClassLoader();
    classFactory = Java.ClassFactory.get(classLoader);
  };
  if (!classFactory) classFactory = Java;
  hookOnClickListener();
}

function hookOnClickListener() {
  // spawn 时机：hook setClickListener 捕获后续设置
  classFactory.use("android.view.View").setOnClickListener.implementation = function (listener) {
    if (listener) watch(listener, "onClick");
    this.setOnClickListener(listener);
  };

  // attach 时机：枚举已有 View 的监听器
  classFactory.choose("android.view.View$ListenerInfo", {
    onMatch: function (instance) {
      const listener = instance.mOnClickListener.value;
      if (listener) watch(listener, 'onClick');
    },
    onComplete: function () { },
  });
}

function watch(obj, mtdName) {
  const listenerClassName = getObjClassName(obj);
  const listenerClass = classFactory.use(listenerClassName);
  listenerClass[mtdName].overloads.forEach(function (overload) {
    overload.implementation = function () {
      console.log(`[*] Watch Event: ${mtdName} - ${getObjClassName(this)}`);
      return this[mtdName].apply(this, arguments);
    };
  })
}

function getObjClassName(obj) {
  const javaClass = classFactory.use("java.lang.Class");
  const javaObject = classFactory.use("java.lang.Object");
  return javaClass.getName.call(javaObject.getClass.call(obj));
}

setImmediate(main);
```

## 7. 启动指定 Activity

```javascript
const targetActivityClassName = "com.example.androiddemo.Activity.FridaActivity5";

setTimeout(function () {
    Java.perform(function () {
        const ActivityThread = Java.use("android.app.ActivityThread");
        const currentApplication = ActivityThread.currentApplication();
        const currentContext = currentApplication.getApplicationContext();

        const Intent = Java.use("android.content.Intent");
        const targetActivityClazz = Java.use(targetActivityClassName).class;
        const newIntent = Intent.$new(currentContext, targetActivityClazz);
        newIntent.setFlags(0x10000000);   // FLAG_ACTIVITY_NEW_TASK

        currentContext.startActivity(newIntent);
    });
}, 2000);
```

## 8. RPC 导出与宿主

JS 端把 Java 静态方法映射为 RPC 导出（导出名用小写，不易出问题）：

```javascript
function addParamSingleStringStaticFuncRpc(className, methodName, exportName) {
  const targetClass = Java.use(className);
  const javaString = Java.use("java.lang.String");
  const rpcMethod = function (str) {
    return targetClass[methodName](javaString.$new(str));
  };
  rpc.exports[exportName] = rpcMethod;
}

Java.perform(function () {
  addParamSingleStringStaticFuncRpc("com.roysue.easyso1.MainActivity", "Sign", "func2");
});
```

Python 宿主（spawn → resume → attach → 调用导出）：

```python
import sys
import time
import frida

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])

# usage: python rpc_host.py com.example.app
if __name__ == '__main__':
    package_name = sys.argv[1]
    device = frida.get_usb_device()
    pid = device.spawn([package_name])
    device.resume(pid)      # 先恢复运行 过几秒再 attach
    time.sleep(2)
    process = device.attach(pid)
    script = process.create_script(jscode)   # jscode 为上面的 JS
    script.on('message', on_message)
    script.load()
    time.sleep(1)
    print(script.exports_sync.func2("requestUserInfo"))
    process.detach()
```

将 RPC 暴露为 HTTP 服务（`pip install "fastapi[standard]"`）：

```python
from fastapi import FastAPI
import uvicorn

# ... 前半部分同上（spawn/attach/load）...

app = FastAPI()

@app.get("/func2/{input_str}")
async def func2(input_str):
    return {"result": script.exports_sync.func2(input_str)}

uvicorn.run(app, host="127.0.0.1", port=8555)
```

同步确定性调用用 `script.exports_sync`，异步长任务用 `script.exports_async`。
