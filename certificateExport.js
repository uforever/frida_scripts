const password = "Zhang3";

function main() {
    Java.perform(function () {
        const application = Java.use("android.app.Application");
        application.attach.overload("android.content.Context").implementation = function (context) {
            this.attach(context);
            const classLoader = context.getClassLoader();
            const classFactory = Java.ClassFactory.get(classLoader);
            hookKeyStore(classFactory);
        };

        // 如果没有壳 可以直接
        // hookKeyStore(Java);
    });
}

const serialNumberSet = new Set();

function exportPkcs12(classFactory, privateKey, certificate, packageName, password) {
    const X509Certificate = classFactory.use("java.security.cert.X509Certificate");
    const certX509 = classFactory.cast(certificate, X509Certificate);
    const serialNumber = certX509.getSerialNumber().toString(16);
    if (!serialNumberSet.has(serialNumber)) {
        const chain = classFactory.array("java.security.cert.X509Certificate", [certX509]);
        const keyStore = classFactory.use("java.security.KeyStore").getInstance("PKCS12", "BC");
        keyStore.load(null, null);
        keyStore.setKeyEntry("client", privateKey, classFactory.use('java.lang.String').$new(password).toCharArray(), chain);
        try {
            const outputPath = `/sdcard/Download/${packageName}.${serialNumber}.p12`;
            const output = classFactory.use("java.io.FileOutputStream").$new(outputPath);
            keyStore.store(output, classFactory.use('java.lang.String').$new(password).toCharArray());
            console.log(`PKCS12 exported to: ${outputPath}`);
            serialNumberSet.add(serialNumber);
        } catch (error) {
            console.error(error);
        }
    }
}

function hookKeyStore(classFactory) {
    classFactory.use("java.security.KeyStore$PrivateKeyEntry").getPrivateKey.implementation = function () {
        const privateKey = this.getPrivateKey();
        const certificate = this.getCertificate();
        const packageName = classFactory.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
        exportPkcs12(classFactory, privateKey, certificate, packageName, password);
        return privateKey;
    };
    classFactory.use("java.security.KeyStore$PrivateKeyEntry").getCertificateChain.implementation = function () {
        const retval = this.getCertificateChain();
        const privateKey = this.getPrivateKey();
        const certificate = this.getCertificate();
        const packageName = classFactory.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
        exportPkcs12(classFactory, privateKey, certificate, packageName, password);
        return retval;
    };
}

setImmediate(main);
