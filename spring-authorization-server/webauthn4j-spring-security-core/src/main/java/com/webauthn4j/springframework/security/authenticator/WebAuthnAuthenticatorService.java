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

package com.webauthn4j.springframework.security.authenticator;

import com.webauthn4j.springframework.security.exception.CredentialIdNotFoundException;

import java.util.List;

/**
 * Core interface for manipulating persisted authenticator
 */
public interface WebAuthnAuthenticatorService {

    /**
     * Updates Authenticator counter
     *
     * @param credentialId credentialId
     * @param counter      counter
     * @throws CredentialIdNotFoundException if the authenticator could not be found
     */
    @SuppressWarnings("squid:RedundantThrowsDeclarationCheck")
    void updateCounter(byte[] credentialId, long counter) throws CredentialIdNotFoundException;

    /**
     * Load {@link WebAuthnAuthenticator} by credentialId
     * @param credentialId credentialId
     * @return {@link WebAuthnAuthenticator}
     * @throws CredentialIdNotFoundException if the authenticator could not be found
     */
    @SuppressWarnings("squid:RedundantThrowsDeclarationCheck")
    WebAuthnAuthenticator loadAuthenticatorByCredentialId(byte[] credentialId) throws CredentialIdNotFoundException;

    /**
     * Load {@link WebAuthnAuthenticator} list by user principal
     * @param principal user principal
     * @return {@link WebAuthnAuthenticator} list
     */
    List<WebAuthnAuthenticator> loadAuthenticatorsByUserPrincipal(Object principal);

}
