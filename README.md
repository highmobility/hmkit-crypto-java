# What is this repository for? #

This repository has the Certificate classes and public Crypto methods(sign, keygen) from the core. It uses HMBTCore for the Crypto methods. The core is expected to be imported from somewhere else(hmkit-cloud.jar or hmkit-android.aar).

## Certificates ##

Access Certificate and Device Certificate are represented in this library. The certificates will always be converted to raw bytes that are accessible with `byte[] getBytes()` method.
You can always add a signature later with `setSignature(byte[])`. You can get the certificate data without 
the signature with getCertificateData().

### AccessCertificate: ###
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

### DeviceCertificate ###
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
public static KeyPair createKeypair()
```

create a random serial number
```java
public static byte[] createSerialNumber()
```

sign

```java
public static byte[] sign(byte[] bytes, byte[] privateKey) 
```


# Dependencies #

* HMBTCore (hmkit-cloud.jar or hmkit-android.aar)
* hmkit-utils.jar