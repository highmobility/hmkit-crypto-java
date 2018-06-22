/*
 * HMKit Crypto - Crypto for Java
 * Copyright (C) 2018 High-Mobility <licensing@high-mobility.com>
 *
 * This file is part of HMKit Crypto.
 *
 * HMKit Crypto is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * HMKit Crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with HMKit Crypto.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.highmobility.crypto;

import com.highmobility.crypto.value.PrivateKey;
import com.highmobility.crypto.value.PublicKey;

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
}
