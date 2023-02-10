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

package com.webauthn4j.springframework.security.anchor;

import com.webauthn4j.anchor.KeyStoreException;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CertificateUtil;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * An implementation of {@link com.webauthn4j.anchor.TrustAnchorsProvider} that loads {@link TrustAnchor}(s) from Java Key Store file in the Spring {@link Resource}
 * @deprecated
 */
@Deprecated
public class KeyStoreResourceTrustAnchorProvider extends com.webauthn4j.anchor.CachingTrustAnchorsProviderBase implements InitializingBean {

    // ~ Instance fields
    // ================================================================================================

    private Resource keyStore;
    private String password;

    // ~ Constructor
    // ========================================================================================================

    public KeyStoreResourceTrustAnchorProvider() {
    }

    public KeyStoreResourceTrustAnchorProvider(Resource keyStore) {
        this.keyStore = keyStore;
    }


    // ~ Methods
    // ========================================================================================================

    @Override
    public void afterPropertiesSet() {
        checkConfig();
    }

    private void checkConfig() {
        AssertUtil.notNull(keyStore, "keyStore must not be null");
    }

    /**
     * Retrieves {@link TrustAnchor}s from Java KeyStore resource.
     *
     * @return null key {@link TrustAnchor} {@link Set} value {@link Map}
     */
    @Override
    protected Map<AAGUID, Set<TrustAnchor>> loadTrustAnchors() {
        checkConfig();
        Resource keystore = getKeyStore();
        try (InputStream inputStream = keystore.getInputStream()) {
            KeyStore keyStoreObject = loadKeyStoreFromStream(inputStream, getPassword());
            List<String> aliases = Collections.list(keyStoreObject.aliases());
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            for (String alias : aliases) {
                X509Certificate certificate = (X509Certificate) keyStoreObject.getCertificate(alias);
                trustAnchors.add(new TrustAnchor(certificate, null));
            }
            return Collections.singletonMap(null, trustAnchors);
        } catch (java.security.KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreException("Failed to load TrustAnchor from keystore", e);
        }
    }

    /**
     * Provides keyStore resource
     *
     * @return keyStore resource
     */
    public Resource getKeyStore() {
        return keyStore;
    }

    /**
     * Sets keyStore resource
     *
     * @param keyStore keyStore resource
     */
    public void setKeyStore(Resource keyStore) {
        this.keyStore = keyStore;
    }

    /**
     * Provides keyStore file password
     *
     * @return keyStore file password
     */
    public String getPassword() {
        return password;
    }

    /**
     * Sets keyStore file password
     *
     * @param password keyStore file password
     */
    public void setPassword(String password) {
        this.password = password;
    }

    private KeyStore loadKeyStoreFromStream(InputStream inputStream, String password)
            throws CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStoreObject = CertificateUtil.createKeyStore();
        keyStoreObject.load(inputStream, password.toCharArray());
        return keyStoreObject;
    }

}
