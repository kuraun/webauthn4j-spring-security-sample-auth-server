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

package com.webauthn4j.springframework.security.endpoint;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.springframework.security.options.AttestationOptions;
import com.webauthn4j.springframework.security.options.AttestationOptionsProvider;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import jakarta.servlet.ServletException;
import java.io.IOException;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.*;

public class AttestationOptionsEndpointFilterTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    @Test
    public void getter_setter_test() {
        AttestationOptionsEndpointFilter optionsEndpointFilter = new AttestationOptionsEndpointFilter(mock(AttestationOptionsProvider.class), objectConverter);
        AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
        optionsEndpointFilter.setTrustResolver(trustResolver);
        assertThat(optionsEndpointFilter.getTrustResolver()).isEqualTo(trustResolver);
    }

    @Test
    public void afterPropertiesSet_test() {
        AttestationOptionsEndpointFilter optionsEndpointFilter = new AttestationOptionsEndpointFilter(mock(AttestationOptionsProvider.class), objectConverter);
        assertThatCode(optionsEndpointFilter::afterPropertiesSet).doesNotThrowAnyException();
    }

    @Test
    public void doFilter_test() throws IOException, ServletException {
        AttestationOptionsProvider optionsProvider = mock(AttestationOptionsProvider.class);
        AttestationOptions attestationOptions = new AttestationOptions(null, null, null, null, null, Collections.emptyList(), null, null, null);
        when(optionsProvider.getAttestationOptions(any(), any())).thenReturn(attestationOptions);
        AttestationOptionsEndpointFilter optionsEndpointFilter = new AttestationOptionsEndpointFilter(optionsProvider, objectConverter);
        AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
        optionsEndpointFilter.setTrustResolver(trustResolver);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(AttestationOptionsEndpointFilter.FILTER_URL);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        optionsEndpointFilter.doFilter(request, response, filterChain);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
    }

    @Test
    public void doFilter_with_unmatched_url_test() throws IOException, ServletException {
        AttestationOptionsProvider optionsProvider = mock(AttestationOptionsProvider.class);
        AttestationOptionsEndpointFilter optionsEndpointFilter = new AttestationOptionsEndpointFilter(optionsProvider, objectConverter);
        AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
        optionsEndpointFilter.setTrustResolver(trustResolver);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/unmatched_url");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        optionsEndpointFilter.doFilter(request, response, filterChain);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
    }

    @Test
    public void doFilter_with_error_test() throws IOException, ServletException {
        AttestationOptionsProvider optionsProvider = mock(AttestationOptionsProvider.class);
        doThrow(new RuntimeException()).when(optionsProvider).getAttestationOptions(any(), any());
        AttestationOptionsEndpointFilter optionsEndpointFilter = new AttestationOptionsEndpointFilter(optionsProvider, objectConverter);
        AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
        optionsEndpointFilter.setTrustResolver(trustResolver);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(AttestationOptionsEndpointFilter.FILTER_URL);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        optionsEndpointFilter.doFilter(request, response, filterChain);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
    }

    @Test
    public void writeErrorResponse_with_RuntimeException_test() throws IOException {
        AttestationOptionsProvider optionsProvider = mock(AttestationOptionsProvider.class);
        AttestationOptionsEndpointFilter optionsEndpointFilter = new AttestationOptionsEndpointFilter(optionsProvider, objectConverter);

        MockHttpServletResponse response = new MockHttpServletResponse();
        RuntimeException exception = new RuntimeException();
        optionsEndpointFilter.writeErrorResponse(response, exception);
        assertThat(response.getContentAsString()).isEqualTo("{\"errorMessage\":\"The server encountered an internal error\"}");
    }

    @Test
    public void writeErrorResponse_with_InsufficientAuthenticationException_test() throws IOException {
        AttestationOptionsProvider optionsProvider = mock(AttestationOptionsProvider.class);
        AttestationOptionsEndpointFilter optionsEndpointFilter = new AttestationOptionsEndpointFilter(optionsProvider, objectConverter);

        MockHttpServletResponse response = new MockHttpServletResponse();
        InsufficientAuthenticationException exception = new InsufficientAuthenticationException(null);
        optionsEndpointFilter.writeErrorResponse(response, exception);
        assertThat(response.getContentAsString()).isEqualTo("{\"errorMessage\":\"Anonymous access is prohibited\"}");
    }

}
