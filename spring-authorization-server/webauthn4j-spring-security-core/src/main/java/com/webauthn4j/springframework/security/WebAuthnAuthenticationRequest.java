/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.springframework.security;

import com.webauthn4j.util.ArrayUtil;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;


/**
 * Internal data transfer object to represent WebAuthn authentication request
 */
public class WebAuthnAuthenticationRequest implements Serializable {

    //~ Instance fields
    // ================================================================================================
    // user inputs
    private final byte[] credentialId;
    private final byte[] clientDataJSON;
    private final byte[] authenticatorData;
    private final byte[] signature;
    private final String clientExtensionsJSON;

    public WebAuthnAuthenticationRequest(byte[] credentialId,
                                         byte[] clientDataJSON,
                                         byte[] authenticatorData,
                                         byte[] signature,
                                         String clientExtensionsJSON) {

        this.credentialId = ArrayUtil.clone(credentialId);
        this.clientDataJSON = ArrayUtil.clone(clientDataJSON);
        this.authenticatorData = ArrayUtil.clone(authenticatorData);
        this.signature = ArrayUtil.clone(signature);
        this.clientExtensionsJSON = clientExtensionsJSON;
    }

    public byte[] getCredentialId() {
        return ArrayUtil.clone(credentialId);
    }

    public byte[] getClientDataJSON() {
        return ArrayUtil.clone(clientDataJSON);
    }

    public byte[] getAuthenticatorData() {
        return ArrayUtil.clone(authenticatorData);
    }

    public byte[] getSignature() {
        return ArrayUtil.clone(signature);
    }

    public String getClientExtensionsJSON() {
        return clientExtensionsJSON;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebAuthnAuthenticationRequest that = (WebAuthnAuthenticationRequest) o;
        return Arrays.equals(credentialId, that.credentialId) &&
                Arrays.equals(clientDataJSON, that.clientDataJSON) &&
                Arrays.equals(authenticatorData, that.authenticatorData) &&
                Arrays.equals(signature, that.signature) &&
                Objects.equals(clientExtensionsJSON, that.clientExtensionsJSON);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(clientExtensionsJSON);
        result = 31 * result + Arrays.hashCode(credentialId);
        result = 31 * result + Arrays.hashCode(clientDataJSON);
        result = 31 * result + Arrays.hashCode(authenticatorData);
        result = 31 * result + Arrays.hashCode(signature);
        return result;
    }
}
