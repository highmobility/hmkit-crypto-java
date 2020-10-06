# HMKit Crypto

This repository contains the Certificate classes and public Crypto methods(sign, keygen).

The library should be accessed from either [hmkit-oem](https://github.com/highmobility/hmkit-oem/blob/1bfca938c495f564934838f10460f35916628f77/hmkit-oem/src/main/java/com/highmobility/hmkit/HMKit.java#L51) or 
[hmkit-android](https://github.com/highmobility/hmkit-android/blob/26fe7293312623a647965cd5f2d6ba9adcb6235f/hmkit-android/src/main/java/com/highmobility/hmkit/HMKit.java#L156). 
It cannot be used independently because it doesn't include the core.

### Dependencies

* [hmkit-core](https://github.com/highmobility/hmkit-core) (from either HMKit Android or HMKit OEM)
* hmkit-utils

### Setup

* Follow the setup process in either HMKit Android or HMKit OEM projects.

### Install

Releases are pushed to jcenter. To include hmkit-crypto in your project, add to build.gradle:

```
repositories {
  jcenter()
}

dependencies {
  // Depending on your environment, use hmkit-oem or hmkit-android to get the transitive crypto
  // dependency 
  // implementation 'com.highmobility:hmkit-oem:2.0.0'
  // or
  // implementation 'com.highmobility:hmkit-android:2.0.3@aar' { transitive = true }
}
```

Find the latest version names in https://bintray.com/high-mobility/maven/

## Certificates

Access Certificate and Device Certificate are represented in this library. The certificates will 
always be converted to raw bytes that are accessible with `Bytes getBytes()` method. You can always 
add a signature later with `setSignature(Signature)`. You can get the certificate data without
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
