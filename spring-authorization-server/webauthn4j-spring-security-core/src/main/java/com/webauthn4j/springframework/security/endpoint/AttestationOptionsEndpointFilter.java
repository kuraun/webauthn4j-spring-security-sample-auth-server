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
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.springframework.security.options.AttestationOptions;
import com.webauthn4j.springframework.security.options.AttestationOptionsProvider;
import org.springframework.security.web.FilterInvocation;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import java.io.IOException;

/**
 * A filter for providing WebAuthn attestation option parameters to clients.
 * Clients can retrieve {@link PublicKeyCredentialCreationOptions}, which includes {@link Challenge}, {@link PublicKeyCredentialRpEntity} and etc.
 */
public class AttestationOptionsEndpointFilter extends AbstractOptionsEndpointFilter {

    // ~ Static fields/initializers
    // =====================================================================================

    /**
     * Default name of path suffix which will validate this filter.
     */
    public static final String FILTER_URL = "/webauthn/attestation/options";

    //~ Instance fields
    // ================================================================================================
    private final AttestationOptionsProvider attestationOptionsProvider;

    public AttestationOptionsEndpointFilter(AttestationOptionsProvider attestationOptionsProvider, ObjectConverter objectConverter) {
        super(objectConverter);
        this.attestationOptionsProvider = attestationOptionsProvider;
        setFilterProcessesUrl(FILTER_URL);
    }

    // ~ Methods
    // ========================================================================================================
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain);

        if (!processFilter(fi.getRequest())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            AttestationOptions attestationOptions = attestationOptionsProvider.getAttestationOptions(fi.getRequest(), getAuthentication());
            writeResponse(fi.getResponse(), attestationOptions);
        } catch (RuntimeException e) {
            logger.debug(e);
            writeErrorResponse(fi.getResponse(), e);
        }

    }

}
