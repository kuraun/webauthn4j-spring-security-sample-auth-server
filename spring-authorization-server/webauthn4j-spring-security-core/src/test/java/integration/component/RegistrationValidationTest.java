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

package integration.component;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidationResponse;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidator;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.test.authenticator.webauthn.PackedAuthenticator;
import com.webauthn4j.test.authenticator.webauthn.WebAuthnAuthenticatorAdaptor;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test for WebAuthnRegistrationContextValidator
 */
public class RegistrationValidationTest {

    final String rpId = "example.com";
    final Challenge challenge = new DefaultChallenge();
    private final Origin origin = new Origin("http://localhost");
    private final WebAuthnAuthenticatorAdaptor webAuthnModelAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(new PackedAuthenticator());
    private final ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnModelAuthenticatorAdaptor);
    private final ServerPropertyProvider serverPropertyProvider = mock(ServerPropertyProvider.class);
    private final WebAuthnRegistrationRequestValidator target = new WebAuthnRegistrationRequestValidator(
            WebAuthnManager.createNonStrictWebAuthnManager(), serverPropertyProvider
    );

    @Test
    public void validate_test() {
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        when(serverPropertyProvider.provide(any())).thenReturn(serverProperty);


        AuthenticatorSelectionCriteria authenticatorSelectionCriteria =
                new AuthenticatorSelectionCriteria(AuthenticatorAttachment.CROSS_PLATFORM, true, UserVerificationRequirement.REQUIRED);

        PublicKeyCredentialParameters publicKeyCredentialParameters = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);

        PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity(new byte[32], "name", "displayName");

        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                publicKeyCredentialUserEntity,
                challenge,
                Collections.singletonList(publicKeyCredentialParameters),
                null,
                null,
                authenticatorSelectionCriteria,
                AttestationConveyancePreference.NONE,
                null
        );

        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();

        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.setScheme("https");
        mockHttpServletRequest.setServerName("example.com");
        mockHttpServletRequest.setServerPort(443);

        String clientDataBase64 = Base64UrlUtil.encodeToString(registrationRequest.getClientDataJSON());
        String attestationObjectBase64 = Base64UrlUtil.encodeToString(registrationRequest.getAttestationObject());
        Set<String> transports = Collections.emptySet();
        String clientExtensionsJSON = null;

        WebAuthnRegistrationRequestValidationResponse response
                = target.validate(mockHttpServletRequest, clientDataBase64, attestationObjectBase64, transports, clientExtensionsJSON);

        assertThat(response.getAttestationObject()).isNotNull();
        assertThat(response.getCollectedClientData()).isNotNull();
        assertThat(response.getRegistrationExtensionsClientOutputs()).isNull();
    }

}
