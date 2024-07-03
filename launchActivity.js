const targetActivityClassName = "com.example.androiddemo.Activity.FridaActivity5";

setTimeout(function () {
    Java.perform(function () {
        // try {

        // 获取当前上下文
        const ActivityThread = Java.use("android.app.ActivityThread");
        const currentApplication = ActivityThread.currentApplication();
        const currentContext = currentApplication.getApplicationContext();

        // 定义新Activity的意图
        const Intent = Java.use("android.content.Intent");
        const targetActivityClazz = Java.use(targetActivityClassName).class;
        const newIntent = Intent.$new(currentContext, targetActivityClazz);
        const FLAG_ACTIVITY_NEW_TASK = 0x10000000;
        newIntent.setFlags(FLAG_ACTIVITY_NEW_TASK);

        currentContext.startActivity(newIntent);
        // } catch (e) { }
    });
}, 2000);