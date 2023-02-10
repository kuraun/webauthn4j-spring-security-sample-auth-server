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

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class WebAuthnAssertionAuthenticationTokenTest {

    @Test(expected = IllegalArgumentException.class)
    public void setAuthenticated_with_true_test() {
        WebAuthnAuthenticationRequest request = mock(WebAuthnAuthenticationRequest.class);
        WebAuthnAuthenticationParameters parameters = mock(WebAuthnAuthenticationParameters.class);
        WebAuthnAssertionAuthenticationToken token = new WebAuthnAssertionAuthenticationToken(request, parameters, null);
        token.setAuthenticated(true);
        assertThat(token.isAuthenticated()).isTrue();
    }

    @Test
    public void setAuthenticated_with_false_test() {
        WebAuthnAuthenticationRequest request = mock(WebAuthnAuthenticationRequest.class);
        WebAuthnAuthenticationParameters parameters = mock(WebAuthnAuthenticationParameters.class);
        WebAuthnAssertionAuthenticationToken token = new WebAuthnAssertionAuthenticationToken(request, parameters, null);
        token.setAuthenticated(false);
        assertThat(token.isAuthenticated()).isFalse();
    }

    @Test
    public void eraseCredentials_test() {
        WebAuthnAuthenticationRequest request = mock(WebAuthnAuthenticationRequest.class);
        WebAuthnAuthenticationParameters parameters = mock(WebAuthnAuthenticationParameters.class);
        WebAuthnAssertionAuthenticationToken token = new WebAuthnAssertionAuthenticationToken(request, parameters, null);
        token.eraseCredentials();
        assertThat(token.getCredentials()).isNull();
    }

    @Test
    public void equals_hashCode_test() {
        WebAuthnAuthenticationRequest request = mock(WebAuthnAuthenticationRequest.class);
        WebAuthnAuthenticationParameters parameters = mock(WebAuthnAuthenticationParameters.class);
        WebAuthnAssertionAuthenticationToken tokenA = new WebAuthnAssertionAuthenticationToken(request, parameters, null);
        WebAuthnAssertionAuthenticationToken tokenB = new WebAuthnAssertionAuthenticationToken(request, parameters, null);

        assertThat(tokenA)
                .isEqualTo(tokenB)
                .hasSameHashCodeAs(tokenB);
    }
}
