package mh.cld.aws.secu.rbac;

import java.util.Arrays;

import org.apache.commons.lang3.builder.RecursiveToStringStyle;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleWithSamlCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithSamlResponse;

@SpringBootApplication
@RestController
public class S3SamlGateway2Application implements CommandLineRunner {
	private String roleArn = "arn:aws:iam::093469567457:role/ADFS-SuperAdmin";
	private String principalArn = "arn:aws:iam::093469567457:saml-provider/production";
	private String samlAssertion = "PHNhbWxwOlJlc3BvbnNlIElEPSJfYjM5ZmRiYjQtMGNiMS00N2I4LWFmOGEtMzM0NDZiMjZjZmFhIiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAyMS0wNS0xN1QxMDozMToyNi41MzdaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9zaWduaW4uYXdzLmFtYXpvbi5jb20vc2FtbCIgQ29uc2VudD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNvbnNlbnQ6dW5zcGVjaWZpZWQiIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxJc3N1ZXIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHA6Ly9zdHMuYjFlbnZlbnVlLmNvbS9hZGZzL3NlcnZpY2VzL3RydXN0PC9Jc3N1ZXI+PHNhbWxwOlN0YXR1cz48c2FtbHA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIiAvPjwvc2FtbHA6U3RhdHVzPjxBc3NlcnRpb24gSUQ9Il8yNGQxNjFlMC03YzJhLTQ3NzctYmQ1YS05NzE2ZTA0MDM2ZjUiIElzc3VlSW5zdGFudD0iMjAyMS0wNS0xN1QxMDozMToyNi41MzdaIiBWZXJzaW9uPSIyLjAiIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj48SXNzdWVyPmh0dHA6Ly9zdHMuYjFlbnZlbnVlLmNvbS9hZGZzL3NlcnZpY2VzL3RydXN0PC9Jc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiIC8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiIC8+PGRzOlJlZmVyZW5jZSBVUkk9IiNfMjRkMTYxZTAtN2MyYS00Nzc3LWJkNWEtOTcxNmUwNDAzNmY1Ij48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiIC8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIgLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIgLz48ZHM6RGlnZXN0VmFsdWU+ZmxYVEpDTExWY3ZyUVVPREZuVnlkRHdPUy83b1hMeVJiOURBbE9UUXI2VT08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+WGZpMFU1OURTNjVXeUc4VytpSWlaaklMbG9xNHZCeWloK242dzM2bm5zZzA3Yk01ZDdqcGFEdU9lY0NCOHYySGpXL1F0UTZPdFFBbjcrSEIrbjNzUUZSZXU5NEJkRFQ0UDNONlZzVzV6Vmh1eUhHZEh2aGFmMFQrKzNXcEJDQkxOODkvdXhEQitFZFFiYmpYdlltekJOWk5LZzRpRVl6eGdNYUdpYjUvTHo4UFRQOEY5eC9kZjE5RnBKbFN5d1d1bFY2SFN5dGp1am9lN282NEpzbllaeUl1eE5ydmQ1M2Q4R3NMMUZZelAyeUQ1MnQ2NlhiNGdQY1ZieFpnT1JBSVZzMEtTNVRadmVUREN0OUgxeFpPRm9HeldlTnUvSEdHWXhaQU4vRUhUK0hBUzlUdXRsMXpmWWhkRmFObTZPWFc1bWFzQXJoWVBRblRvUzVrSmQ5eEV3PT08L2RzOlNpZ25hdHVyZVZhbHVlPjxLZXlJbmZvIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlDM2pDQ0FjYWdBd0lCQWdJUUtqTWVJbXZYVlpsTmVpNE5CR1ZXM2pBTkJna3Foa2lHOXcwQkFRc0ZBREFyTVNrd0p3WURWUVFERXlCQlJFWlRJRk5wWjI1cGJtY2dMU0J6ZEhNdVlqRmxiblpsYm5WbExtTnZiVEFlRncweE9URXlNVEF4T0RFek16RmFGdzB5TVRFeU1Ea3hPREV6TXpGYU1Dc3hLVEFuQmdOVkJBTVRJRUZFUmxNZ1UybG5ibWx1WnlBdElITjBjeTVpTVdWdWRtVnVkV1V1WTI5dE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeTBlamtHaDYyTTBqZWd2ZEMxYWljbzhmekdWRDJoalVKNmYxd2J0NVA4cWlFLzRpMldRb2pldHlzZlEvaUVkK3BUbTJEbDl0aHBRVHh1bGZGWUJzNTd5L2M2KzRMWVBiakpMcXZrRUFCeWtrcUxtVDRZRER6NE83VzAvbFg5TU00M1JacFZVK1BvS3QyQm5JRTZXK0wxYkFVQXFJU0lkblU1NkRua2YzQ3gyb3dvY0pId2p6bWc5K2pWN01uQlFVNEVXc3BkQUJ1MVFMaEIvL0lFVU81Skk3YjdTa2Y1SGtYN1BqUnBQd2h2eHl6akg4M0N3MGQ1YlpiL0k4YklBQklacTE3a1RQQVFEME50TEg5a2NGN2NjR203ZnFBdWw4VjhxZ3BxZE52SnVwZ04yUG1FYXorejQrZWNwNTg5cHdTQTh2cW9MWkVoOGorYXR2bWZzdk9RSURBUUFCTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCSkVkSVNEQ3ZJQXUzeWxnZWRSVFoxZUp6cU9kaWU5NnNCNW1IWkZ5VTMzUWdLNmwvTk9MM3pKNThUTmVWRVZMUytNTGl5V2w0TlNBTzErZi93OFBDZk9LcXdaYUUrV2tCeHVhaVR3TXdFVGNWWlZuelFJbG9xT3dyL21RZzB2NFJPRnJVTlZnQ3krTVFCeUhpclB2cXcrc2pOWXZScGhncldLalFFNkp6NW9KekxSU1A5ZFJTNHVTMTd6djliYmxsc05zQWpKT1hGYjZzVFZlcWFKMWVWSVpxaTl3MlB3TEc0Q29VTFpqZHBCdjdjVHdNdENkTkQyTW1QWDZIYnMxMW03TzZaRE1FZzc2cFpOUkw5T1lYclVTZ25ic2g5L2xlSjJpUWRzSGNNUjM3ZXZadk9neWhIY3ZSZ0MwL2tnL2ppQkJ3b096eXlCZElhd1pOS3pyUVI8L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvS2V5SW5mbz48L2RzOlNpZ25hdHVyZT48U3ViamVjdD48TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6cGVyc2lzdGVudCI+U0kyTVxpZGVpMDgwPC9OYW1lSUQ+PFN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgTm90T25PckFmdGVyPSIyMDIxLTA1LTE3VDEwOjM2OjI2LjUzN1oiIFJlY2lwaWVudD0iaHR0cHM6Ly9zaWduaW4uYXdzLmFtYXpvbi5jb20vc2FtbCIgLz48L1N1YmplY3RDb25maXJtYXRpb24+PC9TdWJqZWN0PjxDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAyMS0wNS0xN1QxMDozMToyNi40NzRaIiBOb3RPbk9yQWZ0ZXI9IjIwMjEtMDUtMTdUMjA6MzE6MjYuNDc0WiI+PEF1ZGllbmNlUmVzdHJpY3Rpb24+PEF1ZGllbmNlPnVybjphbWF6b246d2Vic2VydmljZXM8L0F1ZGllbmNlPjwvQXVkaWVuY2VSZXN0cmljdGlvbj48L0NvbmRpdGlvbnM+PEF0dHJpYnV0ZVN0YXRlbWVudD48QXR0cmlidXRlIE5hbWU9Imh0dHBzOi8vYXdzLmFtYXpvbi5jb20vU0FNTC9BdHRyaWJ1dGVzL1JvbGVTZXNzaW9uTmFtZSI+PEF0dHJpYnV0ZVZhbHVlPm5pY29sYXMudGFyZHlAbWFsYWtvZmZodW1hbmlzLmNvbTwvQXR0cmlidXRlVmFsdWU+PC9BdHRyaWJ1dGU+PEF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlIj48QXR0cmlidXRlVmFsdWU+YXJuOmF3czppYW06OjQ0MDU5ODY2NTEyMjpzYW1sLXByb3ZpZGVyL3Byb2R1Y3Rpb24sYXJuOmF3czppYW06OjQ0MDU5ODY2NTEyMjpyb2xlL0FERlMtU2lBcHBzRFNJQWRtaW48L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5hcm46YXdzOmlhbTo6NDQwNTk4NjY1MTIyOnNhbWwtcHJvdmlkZXIvcHJvZHVjdGlvbixhcm46YXdzOmlhbTo6NDQwNTk4NjY1MTIyOnJvbGUvQURGUy1TdXBlckFkbWluPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+YXJuOmF3czppYW06OjEyMTUwNDQ2MjYyODpzYW1sLXByb3ZpZGVyL3Byb2R1Y3Rpb24sYXJuOmF3czppYW06OjEyMTUwNDQ2MjYyODpyb2xlL0FERlMtU2lBcHBzRFNJQWRtaW48L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5hcm46YXdzOmlhbTo6MTIxNTA0NDYyNjI4OnNhbWwtcHJvdmlkZXIvcHJvZHVjdGlvbixhcm46YXdzOmlhbTo6MTIxNTA0NDYyNjI4OnJvbGUvQURGUy1TdXBlckFkbWluPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+YXJuOmF3czppYW06OjU2MDU4MDY1MzQ4MjpzYW1sLXByb3ZpZGVyL3Byb2R1Y3Rpb24sYXJuOmF3czppYW06OjU2MDU4MDY1MzQ4Mjpyb2xlL0FERlMtU2lBcHBzRFNJQWRtaW48L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5hcm46YXdzOmlhbTo6NTYwNTgwNjUzNDgyOnNhbWwtcHJvdmlkZXIvcHJvZHVjdGlvbixhcm46YXdzOmlhbTo6NTYwNTgwNjUzNDgyOnJvbGUvQURGUy1TdXBlckFkbWluPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+YXJuOmF3czppYW06OjYxMjA5NDY4MDI1ODpzYW1sLXByb3ZpZGVyL3Byb2R1Y3Rpb24sYXJuOmF3czppYW06OjYxMjA5NDY4MDI1ODpyb2xlL0FERlMtU2lBcHBzRFNJQWRtaW48L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5hcm46YXdzOmlhbTo6NjEyMDk0NjgwMjU4OnNhbWwtcHJvdmlkZXIvcHJvZHVjdGlvbixhcm46YXdzOmlhbTo6NjEyMDk0NjgwMjU4OnJvbGUvQURGUy1TdXBlckFkbWluPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+YXJuOmF3czppYW06Ojg5OTgxMDg0NTU4NDpzYW1sLXByb3ZpZGVyL3Byb2R1Y3Rpb24sYXJuOmF3czppYW06Ojg5OTgxMDg0NTU4NDpyb2xlL0FERlMtU2lBcHBzRFNJQWRtaW48L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5hcm46YXdzOmlhbTo6ODk5ODEwODQ1NTg0OnNhbWwtcHJvdmlkZXIvcHJvZHVjdGlvbixhcm46YXdzOmlhbTo6ODk5ODEwODQ1NTg0OnJvbGUvQURGUy1TdXBlckFkbWluPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+YXJuOmF3czppYW06OjU3MDcxNDAxNDczNzpzYW1sLXByb3ZpZGVyL3Byb2R1Y3Rpb24sYXJuOmF3czppYW06OjU3MDcxNDAxNDczNzpyb2xlL0FERlMtQ2xvdWREYXRhQWRtaW48L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5hcm46YXdzOmlhbTo6Mjk1NTgyMzA5MjcxOnNhbWwtcHJvdmlkZXIvcHJvZHVjdGlvbixhcm46YXdzOmlhbTo6Mjk1NTgyMzA5MjcxOnJvbGUvQURGUy1DbG91ZERhdGFBZG1pbjwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPmFybjphd3M6aWFtOjowOTM0Njk1Njc0NTc6c2FtbC1wcm92aWRlci9wcm9kdWN0aW9uLGFybjphd3M6aWFtOjowOTM0Njk1Njc0NTc6cm9sZS9BREZTLUNsb3VkRGF0YUFkbWluPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+YXJuOmF3czppYW06Ojg1NDAyNjA3MTE5NTpzYW1sLXByb3ZpZGVyL3Byb2R1Y3Rpb24sYXJuOmF3czppYW06Ojg1NDAyNjA3MTE5NTpyb2xlL0FERlMtQ2xvdWREYXRhQWRtaW48L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5hcm46YXdzOmlhbTo6NTYyNzAwNzc5MjQ2OnNhbWwtcHJvdmlkZXIvcHJvZHVjdGlvbixhcm46YXdzOmlhbTo6NTYyNzAwNzc5MjQ2OnJvbGUvQURGUy1DbG91ZERhdGFBZG1pbjwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPmFybjphd3M6aWFtOjoxMTgyNDMwNTAxNzg6c2FtbC1wcm92aWRlci9wcm9kdWN0aW9uLGFybjphd3M6aWFtOjoxMTgyNDMwNTAxNzg6cm9sZS9BREZTLUFyY2hzb2xBZG1pbjwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPmFybjphd3M6aWFtOjozMzU0MTQyNzkzMTA6c2FtbC1wcm92aWRlci9wcm9kdWN0aW9uLGFybjphd3M6aWFtOjozMzU0MTQyNzkzMTA6cm9sZS9BREZTLVN1cGVyQWRtaW48L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5hcm46YXdzOmlhbTo6NTYxOTkxODEzNDM4OnNhbWwtcHJvdmlkZXIvcHJvZHVjdGlvbixhcm46YXdzOmlhbTo6NTYxOTkxODEzNDM4OnJvbGUvQURGUy1TdXBlckFkbWluPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+YXJuOmF3czppYW06OjkzNTQyNzMxMzYyNTpzYW1sLXByb3ZpZGVyL3Byb2R1Y3Rpb24sYXJuOmF3czppYW06OjkzNTQyNzMxMzYyNTpyb2xlL0FERlMtU3VwZXJBZG1pbjwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPmFybjphd3M6aWFtOjowOTI5MDA5MDg1MzE6c2FtbC1wcm92aWRlci9wcm9kdWN0aW9uLGFybjphd3M6aWFtOjowOTI5MDA5MDg1MzE6cm9sZS9BREZTLVN1cGVyQWRtaW48L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5hcm46YXdzOmlhbTo6MDkyOTAwOTA4NTMxOnNhbWwtcHJvdmlkZXIvcHJvZHVjdGlvbixhcm46YXdzOmlhbTo6MDkyOTAwOTA4NTMxOnJvbGUvQURGUy1GaW5hbmNlczwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPmFybjphd3M6aWFtOjo2MjA3NzUxMTY0NjI6c2FtbC1wcm92aWRlci9wcm9kdWN0aW9uLGFybjphd3M6aWFtOjo2MjA3NzUxMTY0NjI6cm9sZS9BREZTLVN1cGVyQWRtaW48L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5hcm46YXdzOmlhbTo6MzI2MzQwODM2NjYxOnNhbWwtcHJvdmlkZXIvcHJvZHVjdGlvbixhcm46YXdzOmlhbTo6MzI2MzQwODM2NjYxOnJvbGUvQURGUy1TdXBlckFkbWluPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+YXJuOmF3czppYW06OjMyNjM0MDgzNjY2MTpzYW1sLXByb3ZpZGVyL3Byb2R1Y3Rpb24sYXJuOmF3czppYW06OjMyNjM0MDgzNjY2MTpyb2xlL0FERlMtRmluYW5jZXM8L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5hcm46YXdzOmlhbTo6MzI2MzQwODM2NjYxOnNhbWwtcHJvdmlkZXIvcHJvZHVjdGlvbixhcm46YXdzOmlhbTo6MzI2MzQwODM2NjYxOnJvbGUvQURGUy1EZXZPcHM8L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5hcm46YXdzOmlhbTo6Mjk1NTgyMzA5MjcxOnNhbWwtcHJvdmlkZXIvcHJvZHVjdGlvbixhcm46YXdzOmlhbTo6Mjk1NTgyMzA5MjcxOnJvbGUvQURGUy1TdXBlckFkbWluPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+YXJuOmF3czppYW06Ojg1NDAyNjA3MTE5NTpzYW1sLXByb3ZpZGVyL3Byb2R1Y3Rpb24sYXJuOmF3czppYW06Ojg1NDAyNjA3MTE5NTpyb2xlL0FERlMtU3VwZXJBZG1pbjwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPmFybjphd3M6aWFtOjo4NTQwMjYwNzExOTU6c2FtbC1wcm92aWRlci9wcm9kdWN0aW9uLGFybjphd3M6aWFtOjo4NTQwMjYwNzExOTU6cm9sZS9BREZTLURldk9wczwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPmFybjphd3M6aWFtOjo1NjI3MDA3NzkyNDY6c2FtbC1wcm92aWRlci9wcm9kdWN0aW9uLGFybjphd3M6aWFtOjo1NjI3MDA3NzkyNDY6cm9sZS9BREZTLVN1cGVyQWRtaW48L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5hcm46YXdzOmlhbTo6NTYyNzAwNzc5MjQ2OnNhbWwtcHJvdmlkZXIvcHJvZHVjdGlvbixhcm46YXdzOmlhbTo6NTYyNzAwNzc5MjQ2OnJvbGUvQURGUy1EZXZPcHM8L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5hcm46YXdzOmlhbTo6MDkzNDY5NTY3NDU3OnNhbWwtcHJvdmlkZXIvcHJvZHVjdGlvbixhcm46YXdzOmlhbTo6MDkzNDY5NTY3NDU3OnJvbGUvQURGUy1TdXBlckFkbWluPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+YXJuOmF3czppYW06OjA5MzQ2OTU2NzQ1NzpzYW1sLXByb3ZpZGVyL3Byb2R1Y3Rpb24sYXJuOmF3czppYW06OjA5MzQ2OTU2NzQ1Nzpyb2xlL0FERlMtRGV2T3BzPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHBzOi8vYXdzLmFtYXpvbi5jb20vU0FNTC9BdHRyaWJ1dGVzL1Nlc3Npb25EdXJhdGlvbiI+PEF0dHJpYnV0ZVZhbHVlPjM2MDAwPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48L0F0dHJpYnV0ZVN0YXRlbWVudD48QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIyMDIxLTA1LTE3VDA2OjE1OjUzLjk4MloiIFNlc3Npb25JbmRleD0iXzI0ZDE2MWUwLTdjMmEtNDc3Ny1iZDVhLTk3MTZlMDQwMzZmNSI+PEF1dGhuQ29udGV4dD48QXV0aG5Db250ZXh0Q2xhc3NSZWY+dXJuOmZlZGVyYXRpb246YXV0aGVudGljYXRpb246d2luZG93czwvQXV0aG5Db250ZXh0Q2xhc3NSZWY+PC9BdXRobkNvbnRleHQ+PC9BdXRoblN0YXRlbWVudD48L0Fzc2VydGlvbj48L3NhbWxwOlJlc3BvbnNlPg==";

	@Autowired
	private ApplicationContext appContext;

	public void run(String... strings) {
		Arrays.stream(appContext.getBeanDefinitionNames()).forEach(bean -> {
			ToStringStyle style;
			if (bean.toString().startsWith(
					"spring.security.saml2.relyingparty-org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties")) {
				style = new RecursiveToStringStyle();
			} else {
				style = ToStringStyle.JSON_STYLE;
//				style = new RecursiveToStringStyle(); 
			}
			System.out.println("\t" + ReflectionToStringBuilder.toString(appContext.getBean(bean), style, true, true, true, null));
		});
	}

	public static void main(String[] args) {
		SpringApplication.run(S3SamlGateway2Application.class, args);
	}

	@GetMapping("/")
	public String hello(@RequestParam(value = "name", defaultValue = "World") String name,
			@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal) {
		System.out.println(principal.getName());
		principal.getAttributes().forEach((key, list) -> {
			System.out.println(key);
			list.forEach(item -> {
				System.out.println("\t" + item);
			});
		});

		StsAssumeRoleWithSamlCredentialsProvider.builder();
		StsClient stsClient = StsClient.builder().credentialsProvider(AnonymousCredentialsProvider.create())
				.region(Region.EU_WEST_3).build();
		AssumeRoleWithSamlResponse resp = stsClient.assumeRoleWithSAML(builder -> {
//			String originalInput = "test input";
//			String encodedString = Base64.getEncoder().encodeToString(originalInput.getBytes());
//			String encodedString2 = Base64.getEncoder().withoutPadding().encodeToString(originalInput.getBytes());
//			String originalUrl = "https://www.google.co.nz/?gfe_rd=cr&ei=dzbFV&gws_rd=ssl#q=java";
//			String encodedUrl = Base64.getUrlEncoder().encodeToString(originalUrl.getBytes());

			String samlAssertionb64 = this.samlAssertion;

			builder.roleArn(roleArn).principalArn(principalArn).samlAssertion(samlAssertionb64);
		});

		System.out.println(resp.credentials().accessKeyId());
		System.out.println(resp.credentials().secretAccessKey());
		System.out.println(resp.credentials().sessionToken());

		return String.format("Hello %s!", name);

	}
}