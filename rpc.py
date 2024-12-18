import sys
import time
import frida


# 暂时没用到 可以用来处理更复杂的情况
def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])


jscode = """
// 为只有单个字符串作为参数的静态方法添加RPC
// 根据类名和方法名 导出映射名(最好字母都用小写简单点儿 不容易出问题)
function addParamSingleStringStaticFuncRpc(className, methodName, exportName) {
  const targetClass = Java.use(className);
  const javaString = Java.use("java.lang.String");
  const rpcMethod = function (str) {
    return targetClass[methodName](javaString.$new(str));
  };
  rpc.exports[exportName] = rpcMethod;
}

Java.perform(function () {
  addParamSingleStringStaticFuncRpc("com.roysue.easyso1.MainActivity", "a2w3mtestSign", "func0");
  addParamSingleStringStaticFuncRpc("com.roysue.easyso1.MainActivity", "method01", "func1");
  addParamSingleStringStaticFuncRpc("com.roysue.easyso1.MainActivity", "Sign", "func2");
});
"""

# usage: python rpc.py com.example.app
if __name__ == '__main__':
    try:
        package_name = sys.argv[1]
    except IndexError:
        print("Usage: python rpc.py package_name")
        sys.exit(1)

    # 指定设备
    device = frida.get_usb_device()
    # spawn方式启动程序
    pid = device.spawn([package_name])
    
    # 先恢复程序运行 过几秒再attach
    device.resume(pid)
    time.sleep(2)

    process = device.attach(pid)
    script = process.create_script(jscode)
    script.on('message', on_message)
    script.load()
    print('[*] Loading rpc script')
    time.sleep(1)

    print(script.exports_sync.func0("roysue"))
    print(script.exports_sync.func1("r0syue"))
    print(script.exports_sync.func2("requestUserInfo"))
