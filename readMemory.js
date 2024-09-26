const targetLib = "libcrackme.so";

function main() {
    const baseAddr = Module.findBaseAddress(targetLib);
    console.log("[dylib base address]: ", baseAddr);

    const off_628C = baseAddr.add(0x628C);

    // 看看这个地址是值还是指针
    console.log(off_628C.readCString());
    console.log(off_628C.readPointer());
    
    // 是指针
    console.log(off_628C.readPointer().readCString());
}

setImmediate(main);
