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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity(debug = true)
// see. https://www.baeldung.com/spring-security-registered-filters
public class SecurityConfig 
extends WebSecurityConfigurerAdapter 
{
    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
	
    @Override
	protected void configure(HttpSecurity http) throws Exception {
    	Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver =
    			new DefaultRelyingPartyRegistrationResolver(this.relyingPartyRegistrationRepository);
    	Saml2MetadataFilter filter = new Saml2MetadataFilter(relyingPartyRegistrationResolver, new OpenSamlMetadataResolver());

    	ObjectPostProcessor<AuthenticationEntryPoint> postProcEntryPoint = new ObjectPostProcessor<AuthenticationEntryPoint>() {
			@Override
			public <O extends AuthenticationEntryPoint> O postProcess(O object) {
				((LoginUrlAuthenticationEntryPoint)object).setForceHttps(true);
				return object;
			}
		};
		
	    http
	        .authorizeRequests().anyRequest().authenticated()
	        .and()
	        .saml2Login(saml2conf -> {
	        	saml2conf.addObjectPostProcessor(postProcEntryPoint);
	        	DefaultRedirectStrategy b = new DefaultRedirectStrategy() {
	        		@Override
	        		public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url) throws IOException {
						String lUrl = url;
	        			try {
							URI uri = new URI(url);
							if("http".equals(uri.getScheme())) {
								logger.debug("Force https schema"+ url);
								lUrl = lUrl.replace("http", "https");
							}
						} catch (URISyntaxException e) {
							e.printStackTrace();
						}
	        			super.sendRedirect(request, response, lUrl);
	        		}
	        	};
	        	SavedRequestAwareAuthenticationSuccessHandler a = new SavedRequestAwareAuthenticationSuccessHandler();
	        	a.setRedirectStrategy(b);
	        	saml2conf.successHandler(a);
	        })
	        .addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class);
	}
}
