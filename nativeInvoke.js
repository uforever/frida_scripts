const targetLib = "libCheckRegister.so";

// int sub_1498(char *a1, char *a2)
function sub_1498(arg1, arg2) {
    const baseAddress = Module.findBaseAddress(targetLib);
    console.log("baseAddress: " + baseAddress);

    // KEY: offset
    const offset = 0x1498;
    const targetFuncAddr = baseAddress.add(offset + 1); // 比如使用.add方法 不能直接加

    const targetFunc = new NativeFunction(targetFuncAddr, 'int', ['pointer', 'pointer']);

    const retval = targetFunc(arg1, arg2);
    return retval;
}

function HookNative() {
    console.log("-------- Start Hooking --------");


    const arg1Output = Memory.alloc(100);
    const arg2Passwd = Memory.alloc(100);

    ptr(arg2Passwd).writeUtf8String("MzMz");
    console.log("passwor input: ", arg2Passwd.readUtf8String());
    console.log("before sub_1498 output: " + arg1Output.readUtf8String());


    const retval = sub_1498(arg1Output, arg2Passwd);
    console.log("sub_1498 retval: " + retval);
    console.log("after sub_1498 output: " + arg1Output.readUtf8String());

    console.log("-------- End Hooking --------");

}

// 这里最好设置延迟 否则可能加载不到
setTimeout(HookNative, 3000);