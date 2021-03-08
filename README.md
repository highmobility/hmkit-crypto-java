# HMKit Crypto Telematics

High-Mobility Telematics container, Certificate classes and public Crypto methods(sign, keygen).
It is implemented in pure Java, using BouncyCastle provider.

### Dependencies

* hmkit-utils
* bouncycastle security provider: bcprov-jdk15on

### Setup

* clone the repo
* `./gradlew test`

### Install

Releases are pushed to mavenCentral(). To include hmkit-crypto in your project, add to build.gradle:

```
repositories {
  mavenCentral()
}

dependencies {
  implementation 'com.highmobility:hmkit-crypto-telematics:0.0.1'
}
```

Find the latest version names in mavenCentral.

## Certificates

Access Certificate and Device Certificate are represented in this library. The certificates will
always be converted to raw bytes that are accessible with `Bytes getBytes()` method. You can always
add a signature later with `setSignature(Signature)`. You can get the certificate data without the
signature with getCertificateData().

All the Certificate fields(Issuer, DeviceSerial) also inherit from Bytes class whose methods can be
used for general initialisation, comparison and description.

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

Use Crypto.kt methods to

Create a key pair

```java
public HMKeyPair createKeypair()
```

Create a random serial number

```java
public DeviceSerial createSerialNumber()
```

Sign

```java
public Signature sign(Bytes bytes,PrivateKey privateKey)
```

SignJWT

```kotlin
fun signJWT(message: ByteArray, privateKey: PrivateKey): Signature
```

Get telematics container payload

```kotlin
fun getPayloadFromTelematicsContainer(
    container: Bytes,
    privateKey: PrivateKey,
    accessCertificate: AccessCertificate
): Bytes
```

Create telematics container

```kotlin
fun createTelematicsContainer(
    command: Bytes,
    privateKey: PrivateKey,
    serial: DeviceSerial,
    accessCertificate: AccessCertificate,
    nonce: Bytes
): Bytes
```



