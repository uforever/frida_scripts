function main() {
    Java.perform(() => {
        hookSocket(Java);
    });
}

function hexdump4j(bytes, count) {
    const length = count || bytes.length;
    const blockSize = 16;
    const hex = "0123456789ABCDEF";
    const lines = [];
    lines.push("\n           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF");
    for (let i = 0; i < length; i += blockSize) {
        const block = [];
        for (let j = 0; j < blockSize; j++) {
            block.push(bytes[i + j]);
        }
        const addr = ("00000000" + i.toString(16)).slice(-8);
        let hexCodes = block.map(function (ch) {
            return " " + hex[(0xF0 & ch) >> 4] + hex[0x0F & ch];
        }).join("");
        hexCodes += "   ".repeat(blockSize - block.length);
        let plainChars = block.map(function (ch) {
            if (ch >= 32 && ch <= 126) {
                return String.fromCharCode(ch);
            }
            return ".";
        }).join("");
        plainChars += " ".repeat(blockSize - block.length);
        lines.push(addr + " " + hexCodes + "  " + plainChars);
    }
    return lines.join("\n");
}

function hookSocket(classFactory) {
    const Log = classFactory.use("android.util.Log");
    const Throwable = classFactory.use("java.lang.Throwable");
    const javaHexDump = function (bytes, offset, length) {
        const Hexdump = classFactory.use("com.android.internal.util.HexDump");
        return Hexdump.dumpHexString(bytes, offset, length);
    };

    const Socket = classFactory.use("java.net.Socket");
    const SocketInputStream = classFactory.use("java.net.SocketInputStream");
    const SocketOutputStream = classFactory.use("java.net.SocketOutputStream");
    const Linux = classFactory.use("libcore.io.Linux");
    const NativeCrypto = classFactory.use("com.android.org.conscrypt.NativeCrypto");
    const SSLInputStream = classFactory.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream");
    const SSLOutputStream = classFactory.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream");

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
        console.log(Log.getStackTraceString(Throwable.$new()));
        return this.$init(host, port);
    };
    // 创建一个流套接字并连接到指定地址的指定端口
    Socket.$init.overload("java.net.InetAddress", "int").implementation = function (address, port) {
        // print args
        console.log(`Socket $init("java.net.InetAddress", "int") called with\n\thost: ${address.toString()}\n\tport: ${port}.`);
        // stack trace
        console.log(Log.getStackTraceString(Throwable.$new()));
        return this.$init(address, port);
    };
    // 创建一个流套接字并连接到指定主机的指定端口，使用指定的本地地址和端口
    Socket.$init.overload("java.lang.String", "int", "java.net.InetAddress", "int").implementation = function (host, port, localAddr, localPort) {
        // print args
        console.log(`Socket $init("java.lang.String", "int", "java.net.InetAddress", "int") called with\n\thost: ${host}\n\tport: ${port}\n\tlocalAddr: ${localAddr.toString()}\n\tlocalPort: ${localPort}.`);
        // stack trace
        console.log(Log.getStackTraceString(Throwable.$new()));
        return this.$init(host, port, localAddr, localPort);
    }
    // 创建一个流套接字并连接到指定地址的指定端口，使用指定的本地地址和端口
    Socket.$init.overload("java.net.InetAddress", "int", "java.net.InetAddress", "int").implementation = function (address, port, localAddr, localPort) {
        // print args
        console.log(`Socket $init("java.net.InetAddress", "int", "java.net.InetAddress", "int") called with\n\thost: ${address.toString()}\n\tport: ${port}\n\tlocalAddr: ${localAddr.toString()}\n\tlocalPort: ${localPort}.`);
        // stack trace
        console.log(Log.getStackTraceString(Throwable.$new()));
        return this.$init(address, port, localAddr, localPort);
    };
    hexdump

    // SocketOutputStream的write函数三种重载
    // 不用逐个hook了 直接hook底层原生调用
    /*
    SocketOutputStream.write.overload("int").implementation = function (b) {
        console.log(`SocketOutputStream write("int") called with\n\tb: ${b}.`);
        console.log(Log.getStackTraceString(Throwable.$new()));
        this.write(b);
    }
    SocketOutputStream.write.overload("[B").implementation = function (buffer) {
        console.log(`SocketOutputStream write("[B") called with\n\tbuffer: ${hexdump4j(buffer)}.`);
        console.log(Log.getStackTraceString(Throwable.$new()));
        this.write(buffer);
    };
    SocketOutputStream.write.overload("[B", "int", "int").implementation = function (buffer, offset, length) {
        console.log(`SocketOutputStream write("[B", "int", "int") called with\n\tbuffer: ${hexdump4j(buffer)}\n\toffset: ${offset}\n\tlength: ${length}.`);
        console.log(Log.getStackTraceString(Throwable.$new()));
        this.write(buffer, offset, length);
    };
    */
    // TCP 收发
    // 原生私有函数socketWrite0 没有重载
    SocketOutputStream.socketWrite0.implementation = function (fd, buffer, offset, length) {
        // FileDescriptor 暂时用不到 不打印了
        console.log(`SocketOutputStream socketWrite0 called with\n\tfd\n\tbuffer: ${javaHexDump(buffer, offset, length)}\n\toffset: ${offset}\n\tlength: ${length}.`);
        console.log(Log.getStackTraceString(Throwable.$new()));
        return this.socketWrite0(fd, buffer, offset, length);
    };

    SocketInputStream.socketRead0.implementation = function (fd, buffer, offset, length, timeout) {
        // FileDescriptor 暂时用不到 不打印了
        // const inputStr = javaString.$new(buffer);
        console.log(`SocketInputStream socketRead0 called with\n\tfd\n\tbuffer: ${javaHexDump(buffer, offset, length)}\n\toffset: ${offset}\n\tlength: ${length}\n\ttimeout: ${timeout}.`);
        console.log(Log.getStackTraceString(Throwable.$new()));
        return this.socketRead0(fd, buffer, offset, length, timeout);
    };

    // UDP 发送
    Linux.sendtoBytes.overload("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.InetAddress", "int").implementation = function (fd, buffer, offset, length, flags, inetAddress, port) {
        const bytes = classFactory.array("byte", buffer);
        console.log(`Linux sendtoBytes("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.InetAddress", "int") called with\n\tfd\n\tbuffer: ${javaHexDump(bytes, offset, length)}\n\toffset: ${offset}\n\tlength: ${length}\n\tflags: ${flags}\n\tinetAddress: ${inetAddress}\n\tport: ${port}.`);
        console.log(Log.getStackTraceString(Throwable.$new()));
        return this.sendtoBytes(fd, buffer, offset, length, flags, inetAddress, port);
    };
    // 可能需要把 SocketAddress 通过 classFactory.cast 强转为具体类型 才能调用toString()方法 
    Linux.sendtoBytes.overload("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.SocketAddress").implementation = function (fd, buffer, offset, length, flags, address) {
        const bytes = classFactory.array("byte", buffer);
        console.log(`Linux sendtoBytes("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.SocketAddress") called with\n\tfd\n\tbuffer: ${javaHexDump(bytes, offset, length)}\n\toffset: ${offset}\n\tlength: ${length}\n\tflags: ${flags}\n\taddress: ${address.toString()}.`);
        console.log(Log.getStackTraceString(Throwable.$new()));
        return this.sendtoBytes(fd, buffer, offset, length, flags, address);
    };
    // UDP 接收
    // 最好不写负载 因为不同版本代码有改动
    // Linux.recvfromBytes.overload("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.SocketAddress").implementation = function (fd, buffer, offset, length, flags, srcAddress) {
    // Linux.recvfromBytes.overload("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.InetSocketAddress").implementation = function (fd, buffer, offset, length, flags, srcAddress) {
    Linux.recvfromBytes.implementation = function (fd, buffer, offset, length, flags, srcAddress) {
        const bytes = classFactory.array("byte", buffer);
        // console.log(`Linux recvfromBytes("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.SocketAddress") called with\n\tfd\n\tbuffer: ${hexdump4j(bytes)}\n\toffset: ${offset}\n\tlength: ${length}\n\tflags: ${flags}\n\taddress: ${srcAddress.toString()}.`);
        // console.log(`Linux recvfromBytes("java.io.FileDescriptor", "java.lang.Object", "int", "int", "int", "java.net.InetSocketAddress") called with\n\tfd\n\tbuffer: ${hexdump4j(bytes)}\n\toffset: ${offset}\n\tlength: ${length}\n\tflags: ${flags}\n\taddress: ${srcAddress.toString()}.`);
        console.log(`Linux recvfromBytes called with\n\tfd\n\tbuffer: ${javaHexDump(bytes, offset, length)}\n\toffset: ${offset}\n\tlength: ${length}\n\tflags: ${flags}\n\taddress: ${srcAddress.toString()}.`);
        console.log(Log.getStackTraceString(Throwable.$new()));
        return this.recvfromBytes(fd, buffer, offset, length, flags, srcAddress);
    };

    // SSL
    // conscrypt 如果hook失败 可能是版本不同 参数不一致导致的
    NativeCrypto.SSL_read.implementation = function (ssl, ssl_holder, fd, shc, buffer, offset, length, timeout) {
        console.log(`NativeCrypto SSL_read called with\n\tssl\n\tssl_holder\n\tfd\n\tshc\n\tbuffer: ${javaHexDump(buffer, offset, length)}\n\toffset: ${offset}\n\tlength: ${length}\n\ttimeout: ${timeout}.`);
        console.log(Log.getStackTraceString(Throwable.$new()));
        return this.SSL_read(ssl, ssl_holder, fd, shc, buffer, offset, length, timeout);
    };
    NativeCrypto.SSL_write.implementation = function (ssl, ssl_holder, fd, shc, buffer, offset, length, timeout) {
        console.log(`NativeCrypto SSL_write called with\n\tssl\n\tssl_holder\n\tfd\n\tshc\n\tbuffer: ${javaHexDump(buffer, offset, length)}\n\toffset: ${offset}\n\tlength: ${length}\n\ttimeout: ${timeout}.`);
        console.log(Log.getStackTraceString(Throwable.$new()));
        return this.SSL_write(ssl, ssl_holder, fd, shc, buffer, offset, length, timeout);
    };
    // 下面这两个无需打印参数 因为最后都会调用上面两个已经hook的方法
    // 但是可以获取到socket地址和端口
    SSLInputStream.read.overload('[B', 'int', 'int').implementation = function (buffer, offset, length) {
        // console.log(`SSLInputStream read called with\n\tbuffer: ${hexdump4j(buffer)}\n\toffset: ${offset}\n\tlength: ${length}.`);
        // console.log(Log.getStackTraceString(Throwable.$new()));
        this.read(buffer, offset, length);
    };
    SSLOutputStream.write.overload('[B', 'int', 'int').implementation = function (buffer, offset, length) {
        // console.log(`SSLOutputStream write called with\n\tbuffer: ${hexdump4j(buffer)}\n\toffset: ${offset}\n\tlength: ${length}.`);
        // console.log(Log.getStackTraceString(Throwable.$new()));
        this.write(buffer, offset, length);
    };

    // TODO: SocketInputStream socketRead0 读取数据
    // TODO: SSLInputStream 打印端口
}

setImmediate(main);
