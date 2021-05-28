/*
 * Copyright 2002-2020 the original author or authors.
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

package mh.cld.aws.secu.rbac;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
//	@Bean
//	public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
//		RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistrations
//				.fromMetadataLocation("https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/metadata.php")
//				.registrationId("one")
//				.build();
//		relyingPartyRegistration.getAssertionConsumerServiceBinding();
//		return new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistration);
//	}

    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
    
    @Override
	protected void configure(HttpSecurity http) throws Exception {
    	Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver =
    			new DefaultRelyingPartyRegistrationResolver(this.relyingPartyRegistrationRepository);
    	Saml2MetadataFilter filter = new Saml2MetadataFilter(relyingPartyRegistrationResolver, new OpenSamlMetadataResolver());
    	
	    http
	        .authorizeRequests()
	        .anyRequest().authenticated()
	        .and().saml2Login()
	        .and().addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class);
	}
}
