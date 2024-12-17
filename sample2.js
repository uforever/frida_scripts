// 这个函数提升到全局
let toastPrint = null;

// 调用实例方法 non-static 方法 先选择实例
function invokeInstanceFunc() {
  Java.perform(function () {
    let mainActivity = null;

    Java.choose("com.xiaojianbang.app.MainActivity", {
      onMatch: function (instance) {
        mainActivity = instance;
      },
      onComplete: function () { }
    });

    if (mainActivity) {
      // 调用封装
      toastPrint = function (msg) {
        // 在VM的主线程上运行实例方法
        Java.scheduleOnMainThread(function () {
          // MainActivity.toastPrint.call(mainActivity, "Hello, World!");
          mainActivity.toastPrint(msg);
        });
      };
    }
  });
}

// 调用实例方法的第二种方式 手动创建一个实例
function invokeInstanceFunc2() {
  Java.perform(function () {
    const javaString = Java.use("java.lang.String");
    // 实例方法的另一种调用方式 手动创建一个实例
    // public innerClass(String name, int num)
    const innerClass = Java.use("com.xiaojianbang.app.Money$innerClass");
    const innerClassObj = innerClass.$new(javaString.$new("zhang3"), 22333);
    // 通过创建的实例来调用其方法
    toastPrint("4444");
    toastPrint(innerClassObj.outPrint());
  });
}

// 调用构造方法
function invokeConstructor() {
  Java.perform(function () {
    // const Utils = Java.use("com.xiaojianbang.app.Utils");
    // toastPrint(Utils.getMoney().getInfo());
    // toastPrint(Utils.test(666));

    // 使用$new来调用构造方法 $init来hook构造方法
    const Money = Java.use("com.xiaojianbang.app.Money");
    toastPrint(Money.$new().name());
  });
}

// hook单个实例的方法
function invokeOverloadFunc() {
  Java.perform(function () {
    const Money = Java.use("com.xiaojianbang.app.Money");
    const moneyObj = Money.$new();
    moneyObj.getInfo.implementation = function () {
      return "aloha, 123!";
    };
    toastPrint(moneyObj.getInfo());
  });
}

function mixUse() {
  Java.perform(function () {
    const Utils = Java.use("com.xiaojianbang.app.Utils");
    const Money = Java.use("com.xiaojianbang.app.Money");
    const javaString = Java.use("java.lang.String");

    const moneyObj = Money.$new(javaString.$new("zhang3"), 22333);
    toastPrint(Utils.test(moneyObj));

    const utilsObj = Utils.$new();
    toastPrint(utilsObj.myPrint(
      Java.array("java.lang.String", [
        "hello", " :) ", "frida"
      ])
    ));
  });
}

// hook Native方法
function invokeNativeFunc() {
  let NativeHelper = Java.use("com.xiaojianbang.app.NativeHelper");
  toastPrint(NativeHelper.helloFromC());
}
