# HMKit Crypto

This repository contains the Certificate classes and public Crypto methods(sign, keygen) from the core.
It uses HMBTCore for the Crypto methods. The core is expected to be imported from somewhere
else(hmkit-oem.jar or hmkit-android.aar).

### Dependencies

HMBTCore (from hmkit-oem.jar or hmkit-android.aar), hmkit-utils

### Install

Releases are pushed to jcenter. To include hmkit-crypto in your project, add to build.gradle:

```
repositories {
  jcenter()
}

dependencies {
  // Depending on your environment, either hmkit-oem or hmkit-android is required for the HMBTCore dependency
  // implementation('com.highmobility:hmkit-oem:1.3.0')
  // or
  // implementation 'com.highmobility:hmkit-android:1.3.0@aar'
  implementation('com.highmobility:hmkit-crypto:1.3.2')
}
```

Find the latest version names in https://bintray.com/high-mobility/maven/

## Certificates

Access Certificate and Device Certificate are represented in this library. The certificates will always be converted to raw bytes that are accessible with `Bytes getBytes()` method.
You can always add a signature later with `setSignature(Signature)`. You can get the certificate data without
the signature with getCertificateData().

### AccessCertificate

Use one of the designated initialisers to create the object. For example:

```java
public public AccessCertificate(Issuer issuer,
                                DeviceSerial providingSerial,
                                DeviceSerial gainerSerial,
                                PublicKey gainingPublicKey,
                                HMCalendar startDate,
                                HMCalendar endDate,
                                Permissions permissions)
```

See public getters for certificate info, for example

```java
public Issuer getIssuer()
```

### DeviceCertificate
Use one of the designated initialisers to create the object. For example:

```java
public DeviceCertificate(Issuer issuer,
                         AppIdentifier appIdentifier,
                         DeviceSerial serial,
                         PublicKey publicKey)
```

See public getters for certificate info, for example

```java
public PublicKey getPublicKey()
```

## Crypto ##
Use Crypto.java static methods to

create a key pair
```java
public static HMKeyPair createKeypair()
```

create a random serial number
```java
public static DeviceSerial createSerialNumber()
```

sign

```java
public static Signature sign(Bytes bytes, PrivateKey privateKey)
```

Note that all of the Certificate fields(Issuer, DeviceSerial) inherit from custom Bytes class whose
methods can be used for general initialisation, comparison and description.
