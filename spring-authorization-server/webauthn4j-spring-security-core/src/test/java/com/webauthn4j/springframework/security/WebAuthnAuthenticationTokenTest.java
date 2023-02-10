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

import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.springframework.security.core.userdetails.UserDetails;
import test.TestUserDetailsImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Test for WebAuthnAuthenticationToken
 */
public class WebAuthnAuthenticationTokenTest {

    /**
     * Verifies that constructor with 3 args yields authenticated authenticator.
     */
    @Test
    public void webAuthnAuthenticationToken() {
        WebAuthnAuthenticationToken webAuthnAuthenticationToken = new WebAuthnAuthenticationToken(null, null, null);
        assertThat(webAuthnAuthenticationToken.isAuthenticated()).isTrue();
    }

    @Test
    public void getter_methods() {
        WebAuthnAuthenticationRequest credential = mock(WebAuthnAuthenticationRequest.class);
        UserDetails principal = new TestUserDetailsImpl("username");
        WebAuthnAuthenticationToken webAuthnAuthenticationToken = new WebAuthnAuthenticationToken(principal, credential, null);

        assertThat(webAuthnAuthenticationToken.getPrincipal()).isEqualTo(principal);
        Assertions.assertThat(webAuthnAuthenticationToken.getCredentials()).isEqualTo(credential);
    }

    @Test
    public void equals_hashCode_test() {
        WebAuthnAuthenticationRequest credential = mock(WebAuthnAuthenticationRequest.class);
        WebAuthnAuthenticationToken tokenA = new WebAuthnAuthenticationToken(new TestUserDetailsImpl("username"), credential, null);
        WebAuthnAuthenticationToken tokenB = new WebAuthnAuthenticationToken(new TestUserDetailsImpl("username"), credential, null);
        assertThat(tokenA)
                .isEqualTo(tokenB)
                .hasSameHashCodeAs(tokenB);
    }


}
