/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.springframework.security.WebAuthnAuthenticationProvider;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorManager;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.config.configurers.WebAuthnAuthenticationProviderConfigurer;
import com.webauthn4j.springframework.security.config.configurers.WebAuthnLoginConfigurer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.reactive.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @author Joe Grandja
 * @since 0.1.0
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

	@Autowired
	WebAuthnManager webAuthnManager;

	@Autowired
	WebAuthnAuthenticatorManager webAuthnAuthenticatorManager;

	// @formatter:off
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.apply(WebAuthnLoginConfigurer.webAuthnLogin())
				.attestationOptionsEndpoint()
				.rp()
				.name("WebAuthn4J Spring Security Sample OAuth2")
				.and()
				.pubKeyCredParams(
						new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
						new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS1)
				)
				.attestation(AttestationConveyancePreference.DIRECT)
				.extensions()
				.uvm(true)
				.credProps(true)
				.extensionProviders()
				.and()
				.assertionOptionsEndpoint()
				.extensions()
				.extensionProviders();

		http.authenticationProvider(new WebAuthnAuthenticationProvider(webAuthnAuthenticatorManager, webAuthnManager));

		// WebAuthn
		http.headers(headers -> {
			// 'publickey-credentials-get *' allows getting WebAuthn credentials to all nested browsing contexts (iframes) regardless of their origin.
			headers.permissionsPolicy(config -> config.policy("publickey-credentials-get *"));
			// Disable "X-Frame-Options" to allow cross-origin iframe access
			headers.frameOptions().disable();
		});

		// As WebAuthn has its own CSRF protection mechanism (challenge), CSRF token is disabled here
		http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
		http.csrf().ignoringRequestMatchers("/webauthn/**");

		http.authorizeHttpRequests(authorize ->
						authorize
								.requestMatchers(HttpMethod.GET, "/login").permitAll()
								.requestMatchers(HttpMethod.GET, "/signup").permitAll()
								.requestMatchers(HttpMethod.POST, "/signup").permitAll()
								.requestMatchers("/webjars/**", "/css/**", "/js/**", "/webauthn/**").permitAll()
								.anyRequest().authenticated()
				);

		return http.build();
	}
	// @formatter:on
}
