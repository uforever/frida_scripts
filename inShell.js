Java.perform(() => {
    // 开始定义Hook
    console.log("\n1. Start Hooking");
    var application = Java.use("android.app.Application");
    application.attach.overload("android.content.Context").implementation = function (context) {
        console.log("2. Hooking attach");
        // 执行原来的方法
        this.attach(context);
        var classLoader = context.getClassLoader();
        var classFactory = Java.ClassFactory.get(classLoader);
        var targetClass = classFactory.use("com.example.application.TargetClass");

        targetClass.target.overload().implementation = function () {
            console.log("3. Hooking target function");
            // 父类方法调用
            this.$super.SomeSuperFunc();
        }
    }
});