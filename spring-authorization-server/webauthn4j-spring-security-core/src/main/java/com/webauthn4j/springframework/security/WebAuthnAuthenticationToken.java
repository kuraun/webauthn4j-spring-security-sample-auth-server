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

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Objects;

/**
 * An {@link Authentication} implementation that is designed for Web Authentication specification.
 */
public class WebAuthnAuthenticationToken extends AbstractAuthenticationToken {

    //~ Instance fields
    // ================================================================================================
    @SuppressWarnings("java:S1948")
    private final Object principal;
    private final WebAuthnAuthenticationRequest credentials;

    // ~ Constructor
    // ========================================================================================================

    /**
     * Constructor
     *
     * @param principal   principal
     * @param credentials credentials
     * @param authorities the collection of GrantedAuthority for the principal represented by this authentication object.
     */
    public WebAuthnAuthenticationToken(Object principal, WebAuthnAuthenticationRequest credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        this.setAuthenticated(true);
    }

    // ~ Methods
    // ========================================================================================================

    /**
     * {@inheritDoc}
     */
    @Override
    public Object getPrincipal() {
        return principal;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public WebAuthnAuthenticationRequest getCredentials() {
        return credentials;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof WebAuthnAuthenticationToken)) return false;
        if (!super.equals(o)) return false;

        WebAuthnAuthenticationToken that = (WebAuthnAuthenticationToken) o;

        if (!Objects.equals(principal, that.principal)) return false;
        return Objects.equals(credentials, that.credentials);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (principal != null ? principal.hashCode() : 0);
        result = 31 * result + (credentials != null ? credentials.hashCode() : 0);
        return result;
    }
}
