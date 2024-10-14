function main() {
    Java.perform(() => {
        hookSocket(Java);
    });
}

function hookSocket(classFactory) {
    const Log = classFactory.use("android.util.Log");
    const Throwable = classFactory.use("java.lang.Throwable");
    const Arrays = classFactory.use("java.util.Arrays");
    const Socket = classFactory.use("java.net.Socket");
    const SocketInputStream = classFactory.use("java.net.SocketInputStream");
    const SocketOutputStream = classFactory.use("java.net.SocketOutputStream");
    const Linux = classFactory.use("libcore.io.Linux");

    // hook构造函数的五个重载
    // 通过指定的代理连接到远程主机
    Socket.$init.overload("java.net.Proxy").implementation = function (proxy) {
        // print args
        console.log(`Socket $init("java.net.Proxy") called with\n\tproxy: ${proxy.toString()}.`);
        // console.log(`proxy address: ${proxy.address().toString()}.`);
        // stack trace
        console.log(Throwable.$new().getStackTrace());
        return this.$init(proxy);
    };
    // 创建一个流套接字并连接到指定主机上的指定端口
    Socket.$init.overload("java.lang.String", "int").implementation = function (host, port) {
        // print args
        console.log(`Socket $init("java.lang.String", "int") called with\n\thost: ${host}\n\tport: ${port}.`);
        // stack trace
        Log.getStackTraceString(Throwable.$new());
        return this.$init(host, port);
    };
    // 创建一个流套接字并连接到指定地址的指定端口
    Socket.$init.overload("java.net.InetAddress", "int").implementation = function (address, port) {
        // print args
        console.log(`Socket $init("java.net.InetAddress", "int") called with\n\thost: ${address.toString()}\n\tport: ${port}.`);
        // stack trace
        Log.getStackTraceString(Throwable.$new());
        return this.$init(address, port);
    };
    // 创建一个流套接字并连接到指定主机的指定端口，使用指定的本地地址和端口
    Socket.$init.overload("java.lang.String", "int", "java.net.InetAddress", "int").implementation = function (host, port, localAddr, localPort) {
        // print args
        console.log(`Socket $init("java.lang.String", "int", "java.net.InetAddress", "int") called with\n\thost: ${host}\n\tport: ${port}\n\tlocalAddr: ${localAddr.toString()}\n\tlocalPort: ${localPort}.`);
        // stack trace
        Log.getStackTraceString(Throwable.$new());
        return this.$init(host, port, localAddr, localPort);
    }
    // 创建一个流套接字并连接到指定地址的指定端口，使用指定的本地地址和端口
    Socket.$init.overload("java.net.InetAddress", "int", "java.net.InetAddress", "int").implementation = function (address, port, localAddr, localPort) {
        // print args
        console.log(`Socket $init("java.net.InetAddress", "int", "java.net.InetAddress", "int") called with\n\thost: ${address.toString()}\n\tport: ${port}\n\tlocalAddr: ${localAddr.toString()}\n\tlocalPort: ${localPort}.`);
        // stack trace
        Log.getStackTraceString(Throwable.$new());
        return this.$init(address, port, localAddr, localPort);
    };

    // SocketOutputStream的write函数三种重载
    // 不用逐个hook了 直接hook底层原生调用
    /*
    SocketOutputStream.write.overload("int").implementation = function (b) {
        console.log(`SocketOutputStream write("int") called with\n\tb: ${b}.`);
        Log.getStackTraceString(Throwable.$new());
        this.write(b);
    }
    SocketOutputStream.write.overload("byte[]").implementation = function (buffer) {
        console.log(`SocketOutputStream write("byte[]") called with\n\tbuffer: ${Arrays.toString(buffer)}.`);
        Log.getStackTraceString(Throwable.$new());
        this.write(buffer);
    };
    SocketOutputStream.write.overload("byte[]", "int", "int").implementation = function (buffer, offset, length) {
        console.log(`SocketOutputStream write("byte[]", "int", "int") called with\n\tbuffer: ${Arrays.toString(buffer)}\n\toffset: ${offset}\n\tlength: ${length}.`);
        Log.getStackTraceString(Throwable.$new());
        this.write(buffer, offset, length);
    };
    */
    // TCP 收发
    // 原生私有函数socketWrite0 没有重载
    SocketOutputStream.socketWrite0.implementation = function (fd, buffer, offset, length) {
        // FileDescriptor 暂时用不到 不打印了
        console.log(`SocketOutputStream socketWrite0 called with\n\tfd\n\tbuffer: ${Arrays.toString(buffer)}\n\toffset: ${offset}\n\tlength: ${length}.`);
        Log.getStackTraceString(Throwable.$new());
        this.socketWrite0(fd, buffer, offset, length);
    };

    SocketInputStream.socketRead0.implementation = function (fd, buffer, offset, length, timeout) {
        // FileDescriptor 暂时用不到 不打印了
        console.log(`SocketInputStream socketRead0 called with\n\tfd\n\tbuffer: ${Arrays.toString(buffer)}\n\toffset: ${offset}\n\tlength: ${length}\n\ttimeout: ${timeout}.`);
        Log.getStackTraceString(Throwable.$new());
        this.socketRead0(fd, buffer, offset, length, timeout);
    };

    // UDP 发送
    Linux.sendtoBytes.overload("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.InetAddress", "int").implementation = function (fd, buffer, offset, length, flags, inetAddress, port) {
        const bytes = classFactory.array("byte", buffer);
        console.log(`Linux sendtoBytes("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.InetAddress", "int") called with\n\tfd\n\tbuffer: ${Arrays.toString(bytes)}\n\toffset: ${offset}\n\tlength: ${length}\n\tflags: ${flags}\n\tinetAddress: ${inetAddress}\n\tport: ${port}.`);
        Log.getStackTraceString(Throwable.$new());
        return this.sendtoBytes(fd, buffer, offset, length, flags, inetAddress, port);
    };
    // 可能需要把 SocketAddress 通过 classFactory.cast 强转为具体类型 才能调用toString()方法 
    Linux.sendtoBytes.overload("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.SocketAddress").implementation = function (fd, buffer, offset, length, flags, address) {
        const bytes = classFactory.array("byte", buffer);
        console.log(`Linux sendtoBytes("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.SocketAddress") called with\n\tfd\n\tbuffer: ${Arrays.toString(bytes)}\n\toffset: ${offset}\n\tlength: ${length}\n\tflags: ${flags}\n\taddress: ${address.toString()}.`);
        Log.getStackTraceString(Throwable.$new());
        return this.sendtoBytes(fd, buffer, offset, length, flags, address);
    };
    // UDP 接收
    // 只有一个 不写负载也可以
    Linux.recvfromBytes.overload("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.SocketAddress").implementation = function (fd, buffer, offset, length, flags, srcAddress) {
        const bytes = classFactory.array("byte", buffer);
        console.log(`Linux recvfromBytes("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.SocketAddress") called with\n\tfd\n\tbuffer: ${Arrays.toString(bytes)}\n\toffset: ${offset}\n\tlength: ${length}\n\tflags: ${flags}\n\taddress: ${srcAddress.toString()}.`);
        Log.getStackTraceString(Throwable.$new());
        return this.recvfromBytes(fd, buffer, offset, length, flags, srcAddress);
    };
}

setImmediate(main);
