// frida -U -f com.example.androiddemo -l mTracer.js -o trace.log
// frida -U -F -l mTracer.js -o trace.log
// 需要注意的是 enumerateLoadedClasses 枚举当前加载的类 可能不全
// 最好等相关功能执行后 再进行hook

const allowList = "com.zj.wuaipojie2023_1";
// const denyList = null; // 为空时不进行过滤
const denyList = "$"; // 忽略内部类
const showCallStack = false;

// 带样式输出并保存日志
const styleLog = function (styleName, message) {
  const styles = {
    // text color
    'black': '\x1b[30m',
    'red': '\x1b[31m',
    'green': '\x1b[32m',
    'yellow': '\x1b[33m',
    'blue': '\x1b[34m',
    'magenta': '\x1b[35m',
    'cyan': '\x1b[36m',
    'white': '\x1b[37m',
    'gray': '\x1b[90m',
    'brightRed': '\x1b[91m',
    'brightGreen': '\x1b[92m',
    'brightYellow': '\x1b[93m',
    'brightBlue': '\x1b[94m',
    'brightMagenta': '\x1b[95m',
    'brightCyan': '\x1b[96m',
    'brightWhite': '\x1b[97m',

    // background color
    'bgBlack': '\x1b[40m',
    'bgRed': '\x1b[41m',
    'bgGreen': '\x1b[42m',
    'bgYellow': '\x1b[43m',
    'bgBlue': '\x1b[44m',
    'bgMagenta': '\x1b[45m',
    'bgCyan': '\x1b[46m',
    'bgWhite': '\x1b[47m',
    'bgGray': '\x1b[100m',
    'bgBrightRed': '\x1b[101m',
    'bgBrightGreen': '\x1b[102m',
    'bgBrightYellow': '\x1b[103m',
    'bgBrightBlue': '\x1b[104m',
    'bgBrightMagenta': '\x1b[105m',
    'bgBrightCyan': '\x1b[106m',
    'bgBrightWhite': '\x1b[107m',

    // other style
    'reset': '\x1b[0m',         // reset / default
    'bold': '\x1b[1m',          // bold
    'dim': '\x1b[2m',           // dim
    'italic': '\x1b[3m',        // italic
    'underline': '\x1b[4m',     // underline
    'inverse': '\x1b[7m',       // inverse
    'hidden': '\x1b[8m',        // hidden
    'strikethrough': '\x1b[9m', // strikethrough
  };
  if (!styles[styleName]) {
    console.error(`Invalid styleName for styleLog: \`${styleName}\``);
    console.log(message);
  } else {
    console.log(`${styles[styleName]}${message}${styles.reset}`);
  }
};

// hook Java 函数
// Java.perform(function () { hookJavaMethod("areEqual", null,"kotlin.jvm.internal.Intrinsics"); });
const hookJavaMethod = function (methodName, targetClass, className) {
  const target = targetClass || Java.use(className);
  const overloads = target[methodName].overloads;
  // 遍历hook所有重载方法
  for (const overload of overloads) {
    overload.implementation = function () {
      const retval = overload.apply(this, arguments);

      // 打印 参数、调用栈、返回值
      const methodSign = overload.toString();
      styleLog('magenta', `\n-------- ${methodSign.replace("function ", className + ".")} ----------`);
      styleLog('magenta', `[arguments]:`);
      for (const arg of arguments) {
        // styleLog('magenta', `  - ${JSON.stringify(arg)}`);
        styleLog('magenta', `  - ${arg.toString()}`);
      }
      if (showCallStack) {
        const callStack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
        styleLog('magenta', `[call stack]:\n${callStack}`);
      }
      // styleLog('magenta', `[return value]:\n${JSON.stringify(retval, null, 2)}`);
      if (retval !== undefined) {
        styleLog('magenta', `[return value]:\n${retval.toString()}`);
      }
      return retval;
    };
  }
}

// hook Java 类
// Java.perform(function () { hookJavaClass("kotlin.jvm.internal.Intrinsics", Java); });
const hookJavaClass = function (className, classFactory) {
  styleLog('green', `\n-------- ${className} ----------`);
  const targetClass = classFactory.use(className);
  const targetClazz = targetClass.class;
  const methods = targetClazz.getDeclaredMethods();
  const constructors = targetClazz.getDeclaredConstructors();

  // 方法名去重
  const methodNames = new Set(methods.map(function (method) {
    styleLog('green', method.toString());
    return method.getName();
  }));

  if (constructors.length > 0) {
    // 如果有构造函数，则添加一个$init方法名
    methodNames.add("$init");
    for (const constructor of constructors) {
      styleLog('green', constructor.toString());
    }
  }

  styleLog('green', `\n-------- ${'-'.repeat(className.length)} ----------`);

  for (const methodName of methodNames) {
    hookJavaMethod(methodName, targetClass, className);
  }
}

// hook安卓
const hookAndroid = function (allowList, denyList) {
  Java.perform(function () {
    styleLog('cyan', '\n-------- Hooking Android --------');

    // 找到满足要求的全部类并输出
    let targetClasses = new Array();
    Java.enumerateLoadedClasses({
      onMatch: function (name, _handle) {
        if (name.includes(allowList) && !name.includes(denyList)) {
          targetClasses.push(name);
        }
      },
      onComplete: function () { } // 必须加 不然会报错
    });
    styleLog('cyan', `Found ${targetClasses.length} target classes:`);
    targetClasses.forEach(function (name) {
      styleLog('cyan', `  - ${name}`);
    });

    // 遍历全部ClassLoader批量hook Java类
    Java.enumerateClassLoaders({
      onMatch: function (loader) {
        const classFactory = Java.ClassFactory.get(loader);
        targetClasses = targetClasses.filter(function (name) {
          try {
            if (loader.findClass(name)) {
              // hook单个Java类
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

const hookIOS = function (_allowList, _denyList) {
  styleLog('red', 'Error: iOS hooking is not supported yet!');
};

const hook = function (allowList, denyList) {
  if (Java.available) {
    hookAndroid(allowList, denyList);
  } else if (ObjC.available) {
    hookIOS(allowList, denyList);
  } else {
    styleLog('red', 'Error: No runtime available!');
  }
};

const main = function () {
  styleLog('white', '\n-------- Start tracing --------');
  // hook -> hookAndroid -> hookJavaClass -> hookJavaMethod
  // hook(allowList, denyList); // 手动执行这条命令
};

setImmediate(main);
