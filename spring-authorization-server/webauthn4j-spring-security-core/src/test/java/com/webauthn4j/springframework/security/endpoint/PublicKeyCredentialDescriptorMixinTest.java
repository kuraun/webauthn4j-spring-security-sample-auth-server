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


import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialType;
import org.junit.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

public class PublicKeyCredentialDescriptorMixinTest {

    @Test
    public void test(){
        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.addMixIn(PublicKeyCredentialDescriptor.class, PublicKeyCredentialDescriptorMixin.class);
        ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
        ObjectConverter objectConverter = new ObjectConverter(jsonMapper, cborMapper);

        PublicKeyCredentialDescriptor publicKeyCredentialDescriptor = new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, new byte[32], Collections.singleton(AuthenticatorTransport.INTERNAL));
        String json = objectConverter.getJsonConverter().writeValueAsString(publicKeyCredentialDescriptor);
        assertThat(json).isEqualTo("{\"type\":\"public-key\",\"id\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"transports\":[\"internal\"]}");
        assertThat(objectConverter.getJsonConverter().readValue(json, PublicKeyCredentialDescriptor.class)).isEqualTo(publicKeyCredentialDescriptor);
    }

}