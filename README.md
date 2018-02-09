# HMKit Crypto

This repository has the Certificate classes and public Crypto methods(sign, keygen) from the core. It uses HMBTCore for the Crypto methods. The core is expected to be imported from somewhere else(hmkit-oem.jar or hmkit-android.aar).

### Dependencies

HMBTCore (from hmkit-oem.jar or hmkit-android.aar), hmkit-utils

### Install

Releases are pushed to jcenter. To include hmkit-crypto in your project, add to build.gradle:

```
repositories {
  jcenter()
}

dependencies {
  implementation('com.highmobility:hmkit-crypto:1.1.9')
  // Depending on your environment, either hmkit-oem or hmkit-android is required for the HMBTCore dependency
  // implementation('com.highmobility:hmkit-oem:1.1.2')
  // or
  // implementation 'com.highmobility:hmkit-android:1.1.11@aar'
}
```

Find the latest version names in https://bintray.com/high-mobility/maven/

## Certificates

Access Certificate and Device Certificate are represented in this library. The certificates will always be converted to raw bytes that are accessible with `byte[] getBytes()` method.
You can always add a signature later with `setSignature(byte[])`. You can get the certificate data without 
the signature with getCertificateData().

### AccessCertificate
Use one of the designated initializers to create the object. For example:

```java
public AccessCertificate(byte[] gainerSerial,
                             byte[] gainingPublicKey,
                             byte[] providingSerial,
                             byte[] startDate,
                             byte[] endDate,
                             byte[] permissions) throws IllegalArgumentException {
```

See public getters for certificate info, for example

```java
public byte[] getIssuer()
```

### DeviceCertificate
Use one of the designated initializers to create the object. For example:

```java
public DeviceCertificate(byte[] issuer,
                             byte[] appIdentifier,
                             byte[] serial,
                             byte[] publicKey) throws IllegalArgumentException
```

See public getters for certificate info, for example

```java
public byte[] getPublicKey()
```

## Crypto ##
Use Crypto.java static methods to

create a key pair
```java
public static HMKeyPair createKeypair()
```

create a random serial number
```java
public static byte[] createSerialNumber()
```

sign

```java
public static byte[] sign(byte[] bytes, byte[] privateKey) 
```
