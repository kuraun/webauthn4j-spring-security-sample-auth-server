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

package com.webauthn4j.springframework.security.converter;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import org.springframework.core.convert.converter.Converter;

/**
 * Spring converter which converts from Base64Url {@link String} to {@link AttestationObject}
 */
public class Base64UrlStringToAttestationObjectConverter implements Converter<String, AttestationObject> {

    //~ Instance fields
    // ================================================================================================
    private final AttestationObjectConverter converter;

    // ~ Constructor
    // ========================================================================================================

    public Base64UrlStringToAttestationObjectConverter(ObjectConverter objectConverter) {
        converter = new AttestationObjectConverter(objectConverter);
    }

    /**
     * Convert Base64Url {@link String} to {@link AttestationObject}
     *
     * @param source base64String
     * @return attestationObject
     */
    @Override
    public AttestationObject convert(String source) {
        return converter.convert(source);
    }

}
