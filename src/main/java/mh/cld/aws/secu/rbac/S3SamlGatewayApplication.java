package mh.cld.aws.secu.rbac;


import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.servlet.Filter;

import org.apache.commons.lang.builder.ReflectionToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.debug.DebugFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleWithSamlCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithSamlResponse;

// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html#saml_audience-restriction
// DO NOT FORGET: set following condition in your SAML Role policy trust relationship:	
// "Condition": {
// 	"StringEquals": {
// 	  "SAML:aud": "<YOUR_SAML_RESPONSE_Subject/SubjectConfirmation/SubjectConfirmationData/@Recipient[text()]>"
// 	}
@SpringBootApplication
@RestController
public class S3SamlGatewayApplication implements CommandLineRunner {
	private static final Logger log = LoggerFactory.getLogger(S3SamlGatewayApplication.class);

	@Autowired
	private ApplicationContext appContext;
	@Autowired
	private Filter springSecurityFilterChain;

	private void getBeans() {
		Arrays.stream(appContext.getBeanDefinitionNames()).forEach(bean -> 
			log.trace("\t{}", ReflectionToStringBuilder.toString(appContext.getBean(bean), ToStringStyle.MULTI_LINE_STYLE))
		);
	}

	private void getFilters() {
		if (this.springSecurityFilterChain.getClass() != DebugFilter.class) {
			FilterChainProxy filterChainProxy = (FilterChainProxy) springSecurityFilterChain;
			List<SecurityFilterChain> list = filterChainProxy.getFilterChains();
			list.stream().flatMap(chain -> chain.getFilters().stream())
					.forEach(filter -> log.debug(filter.getClass().toString()));
		}
	}

	public void run(String... strings) {
		getBeans();
		getFilters();
	}

	public static void main(String[] args) {
		SpringApplication.run(S3SamlGatewayApplication.class, args);
	}


	@GetMapping(value = "/{fileName}")
	public ResponseEntity<StreamingResponseBody> stream(
			@RequestParam(value = "roleArn", defaultValue = "arn:aws:iam::118243050178:role/ADFS-PocS3gateway") String roleArn, 
			@RequestParam(value = "principalArn", defaultValue = "arn:aws:iam::118243050178:saml-provider/adfs") String principalArn, 
			@RequestParam(value = "bucketName", defaultValue = "test-speechanalytics-web-hosting") String bucketName, 
			@PathVariable(value = "fileName") String fileName, 
			@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, 
			@CurrentSecurityContext SecurityContext secCxt) {
//		String fileName = "Miaow-01-Tempered-song.mp3";

		String contentType = "audio/" + fileName.substring(fileName.lastIndexOf(".")+1);
		log.debug("File to read: '{}'",fileName);
		log.debug("In bucket: '{}'",bucketName);
		log.trace("With role: '{}'",roleArn);
		log.trace("From provider: '{}'",fileName);
		log.debug("Content-Type: '{}'", contentType);

		Region region = Region.EU_WEST_3;
		String samlResponse = ((Saml2Authentication) secCxt.getAuthentication()).getSaml2Response();
		AwsCredentials awsCreds = getAwsCredentials(roleArn, principalArn, samlResponse, region);
		
		StreamingResponseBody responseBody = response -> {
			try (
				S3Client s3client = getS3client(awsCreds, region); 
				ResponseInputStream<GetObjectResponse> audioIs = getS3Object(bucketName, fileName, s3client);
				BufferedInputStream bufis = new BufferedInputStream(audioIs);
				BufferedOutputStream bufos = new BufferedOutputStream(response)
			) {
				for (int i = bufis.read(); i != -1; i = bufis.read()) {
					bufos.write(i);
				}
			}
		};
		return ResponseEntity.ok().header( "Content-Type", contentType).body(responseBody);
	}
	
	private ResponseInputStream<GetObjectResponse> getS3Object(String bucketName, String fileName, S3Client s3client) {
		ResponseInputStream<GetObjectResponse> audioIs = s3client.getObject(
				b -> b.bucket(bucketName).key(fileName),
				ResponseTransformer.toInputStream()
			);
		return audioIs;
	}
	
	private S3Client getS3client(AwsCredentials awsCreds, Region region) {
		S3Client s3client = S3Client.builder()
				.region(region)
				.credentialsProvider(StaticCredentialsProvider.create(awsCreds))
				.build();
		return s3client;
	}
	
	private AwsCredentials getAwsCredentials(String roleArn, String principalArn, String samlResponse, Region region) {
		StsAssumeRoleWithSamlCredentialsProvider.builder();
		StsClient stsClient = StsClient.builder().credentialsProvider(AnonymousCredentialsProvider.create()).region(region).build();
		AssumeRoleWithSamlResponse resp = stsClient.assumeRoleWithSAML(builder -> {
			String samlAssertionb64 = Base64.getEncoder().encodeToString(samlResponse.getBytes());
			builder.roleArn(roleArn).principalArn(principalArn).samlAssertion(samlAssertionb64);
		});

		log.debug("accessKeyId: {}", resp.credentials().accessKeyId());
		log.debug("secretAccessKey: {}", resp.credentials().secretAccessKey());
		log.debug("sessionToken: {}", resp.credentials().sessionToken());
				
		String accessKey = resp.credentials().accessKeyId();
		String secretKey = resp.credentials().secretAccessKey();
		String sessionToken = resp.credentials().sessionToken();
		
		AwsCredentials awsCreds = AwsSessionCredentials.create(accessKey, secretKey, sessionToken);
		return awsCreds;
	}

	// @GetMapping("/")
	// public String hello(@RequestParam(value = "name", defaultValue = "World") String name,
	// 		@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal,
	// 		@CurrentSecurityContext SecurityContext secCxt) {
	// 	log.debug(principal.getName());
	// 	principal.getAttributes().forEach((key, list) -> {
	// 		log.debug(key);
	// 		list.forEach(item -> log.debug("\t{}", item));
	// 	});

	// 	String samlResponse = ((Saml2Authentication) secCxt.getAuthentication()).getSaml2Response();
	// 	StsAssumeRoleWithSamlCredentialsProvider.builder();
	// 	StsClient stsClient = StsClient.builder().credentialsProvider(AnonymousCredentialsProvider.create())
	// 			.region(Region.EU_WEST_3).build();
	// 	AssumeRoleWithSamlResponse resp = stsClient.assumeRoleWithSAML(builder -> {
	// 		String roleArn = "arn:aws:iam::118243050178:role/ADFS-PocS3gateway";
	// 		String principalArn = "arn:aws:iam::118243050178:saml-provider/adfs";
	// 		String samlAssertionb64 = Base64.getEncoder().encodeToString(samlResponse.getBytes());
	// 		builder.roleArn(roleArn).principalArn(principalArn).samlAssertion(samlAssertionb64);
	// 	});

	// 	log.debug("accessKeyId: {}", resp.credentials().accessKeyId());
	// 	log.debug("secretAccessKey: {}", resp.credentials().secretAccessKey());
	// 	log.debug("sessionToken: {}", resp.credentials().sessionToken());

	// 	return String.format("Hello %s!", principal.getName() + " on Relying Party / Service Provider audience '" + resp.audience() +"'");
	// }


}
