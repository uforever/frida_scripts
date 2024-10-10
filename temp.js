const password = "Zhang3";

function hashCertificate(classFactory, certificate) {
    const MessageDigest = classFactory.use("java.security.MessageDigest");
    const digest = MessageDigest.getInstance("SHA-256");
    const certBytes = certificate.getEncoded();
    const hash = digest.digest(certBytes);
    return hash.toString();
}

function exportPkcs12(classFactory, privateKey, certificate, outputPath, password) {
    const X509Certificate = classFactory.use("java.security.cert.X509Certificate");
    const certX509 = classFactory.cast(certificate, X509Certificate);
    const chain = classFactory.array("java.security.cert.X509Certificate", [certX509]);
    const keyStore = classFactory.use("java.security.KeyStore").getInstance("PKCS12", "BC");
    keyStore.load(null, null);
    keyStore.setKeyEntry("client", privateKey, classFactory.use('classFactory.lang.String').$new(password).toCharArray(), chain);
    try {
        const output = classFactory.use("classFactory.io.FileOutputStream").$new(outputPath);
        keyStore.store(output, classFactory.use('classFactory.lang.String').$new(password).toCharArray());
        console.log("dump success!");
    } catch (error) {
        console.error(error);
    }
}

function hookKeyStore(classFactory) {
    classFactory.use("java.security.KeyStore$PrivateKeyEntry").getPrivateKey.implementation = function () {
        const privateKey = this.getPrivateKey();
        const certificate = this.getCertificate();
        console.log(JSON.stringify(certificate));
        const packageName = classFactory.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
        exportPkcs12(classFactory, privateKey, certificate, packageName, password);
        return privateKey;
    };
    classFactory.use("java.security.KeyStore$PrivateKeyEntry").getCertificateChain.implementation = function () {
        const retval = this.getCertificateChain();

        const privateKey = this.getPrivateKey();
        const certificate = this.getCertificate();
        console.log(JSON.stringify(certificate));
        const packageName = classFactory.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
        exportPkcs12(classFactory, privateKey, certificate, packageName, password);
        return retval;
    };
}

function main() {
    Java.perform(function () {
        const application = Java.use("android.app.Application");
        application.attach.overload("android.content.Context").implementation = function (context) {
            this.attach(context);
            const classLoader = context.getClassLoader();
            console.log("classLoader");
            const classFactory = Java.ClassFactory.get(classLoader);
            hookKeyStore(classFactory);
        };

        // 如果没有壳 可以直接
        // hookKeyStore(Java);
    });
}

setImmediate(main);
