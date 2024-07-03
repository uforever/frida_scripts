Java.perform(() => {
    console.log("-------- Start Hooking --------");

    // target class
    const FridaActivity1 = Java.use("com.example.androiddemo.Activity.FridaActivity1");
    const FridaActivity2 = Java.use("com.example.androiddemo.Activity.FridaActivity2");
    const FridaActivity3 = Java.use("com.example.androiddemo.Activity.FridaActivity3");
    // const FridaActivity4 = Java.use("com.example.androiddemo.Activity.FridaActivity4");
    // inner class
    const FridaActivity4_InnerClasses = Java.use("com.example.androiddemo.Activity.FridaActivity4$InnerClasses");
    const FridaActivity5 = Java.use("com.example.androiddemo.Activity.FridaActivity5");
    const FridaActivity6 = Java.use("com.example.androiddemo.Activity.FridaActivity6");

    // hook static field
    FridaActivity3.static_bool_var.value = true;

    // 枚举内存中的现有实例
    // Java.choose("com.example.androiddemo.Activity.FridaActivity2", {
    //     onMatch: function (instance) {
    //         instance.setBool_var();
    //         instance.bool_var.value = true;
    //     },
    //     onComplete: function () { },
    // });

    // 实例初始化时进行Hook
    FridaActivity2.$init.overload().implementation = function () {
        this.$init();
        // invoke non-static method
        this.setBool_var();
    }

    FridaActivity3.$init.overload().implementation = function () {
        this.$init();
        // hook non-static field
        this.bool_var.value = true;
        // this.same_name_bool_var();
        // 存在同名函数的情况下 加上_前缀
        this._same_name_bool_var.value = true;
        // this.same_name_bool_var();
    }

    // invoke static method
    FridaActivity2.setStatic_bool_var();

    // hook static method
    FridaActivity1.a.implementation = function (bArr) {
        return "R4jSLLLLLLLLLLOrLE7/5B+Z6fsl65yj6BgC6YWz66gO6g2t65Pk6a+P65NK44NNROl0wNOLLLL=";
    };

    // FridaActivity4_InnerClasses.check1.implementation = function () {
    //     return true;
    // }
    // FridaActivity4_InnerClasses.check2.implementation = function () {
    //     return true;
    // }
    // FridaActivity4_InnerClasses.check3.implementation = function () {
    //     return true;
    // }
    // FridaActivity4_InnerClasses.check4.implementation = function () {
    //     return true;
    // }
    // FridaActivity4_InnerClasses.check5.implementation = function () {
    //     return true;
    // }
    // FridaActivity4_InnerClasses.check6.implementation = function () {
    //     return true;
    // }

    // batch hook method
    const methods = FridaActivity4_InnerClasses.class.getDeclaredMethods();
    for (const method of methods) {
        const methodName = method.getName();
        if (methodName.startsWith("check")) {
            FridaActivity4_InnerClasses[methodName].implementation = function () {
                return true;
            }
        }
    }

    // current classloader
    // console.log(Java.classFactory.loader);
    // 记录默认的classloader
    // const temp = Java.classFactory.loader;
    // enumearte methods
    // console.log(JSON.stringify(Java.enumerateMethods("*!check"), null, 2));

    // hook 动态加载的内容
    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            try {
                if (loader.findClass("com.example.androiddemo.Dynamic.DynamicCheck")) {
                    // console.log("DynamicCheck found in " + loader);
                    // 可以修改默认的classloader 后续直接Java.use即可
                    // Java.classFactory.loader = loader;
                    // Java.use("com.example.androiddemo.Dynamic.DynamicCheck").check.implementation = function () {
                    //     return true;
                    // }
                    // 恢复默认的classloader
                    // Java.classFactory.loader = temp;

                    // 也可以通过ClassFactory直接进行交互
                    const classFactory = Java.ClassFactory.get(loader);
                    const DynamicCheck = classFactory.use("com.example.androiddemo.Dynamic.DynamicCheck");
                    DynamicCheck.check.implementation = function () {
                        return true;
                    };
                }
            } catch (e) { }
        },
        onComplete: function () { } // 必须加 不然会报错
    });


    // Java.use("com.example.androiddemo.Activity.Frida6.Frida6Class0").check.implementation = function () { return true };
    // Java.use("com.example.androiddemo.Activity.Frida6.Frida6Class1").check.implementation = function () { return true };
    // Java.use("com.example.androiddemo.Activity.Frida6.Frida6Class2").check.implementation = function () { return true };

    // batch hook loaded classes
    Java.enumerateLoadedClasses({
        onMatch: function (name, _handle) {
            if (name.includes("com.example.androiddemo.Activity.Frida6.Frida6Class")) {
                // console.log(name);
                Java.use(name).check.implementation = function () {
                    return true;
                }
            }
        },
        onComplete: function () { } // 必须加 不然会报错
    });

    // console.log(JSON.stringify(Java.enumerateMethods("*Frida6*!check"), null, 2));

    // enum loaded methods
    // const loaderClassesArray = Java.enumerateMethods("*Frida6*!check");
    // for (const loaderClasses of loaderClassesArray) {
    //     const loader = loaderClasses.loader;
    //     const classFactory = Java.ClassFactory.get(loader);
    //     const classes = loaderClasses.classes;
    //     for (const clazz of classes) {
    //         const className = clazz.name;
    //         classFactory.use(className).check.implementation = function () {
    //             return true;
    //         }
    //     }
    // }

});