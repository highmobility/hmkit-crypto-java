/*
 * The MIT License
 *
 * Copyright (c) 2014- High-Mobility GmbH (https://high-mobility.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.highmobility.cryptok;

import com.highmobility.cryptok.value.PrivateKey;
import com.highmobility.cryptok.value.PublicKey;

/**
 * ECC private/public keypair that uses elliptic curve P-256.
 */
public class HMKeyPair {
    private static final long serialVersionUID = 6637283024188232326L;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    /**
     * Create a ECC Keypair object with private and public key.
     *
     * @param privateKey The private key.
     * @param publicKey  The public key.
     * @throws IllegalArgumentException When the keys are invalid.
     */
    public HMKeyPair(PrivateKey privateKey, PublicKey publicKey) throws IllegalArgumentException {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * @return The public key.
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * @return The private key.
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override public String toString() {
        return "HMKeyPair{" +
                "privateKey=" + privateKey +
                ", publicKey=" + publicKey +
                '}';
    }
}
