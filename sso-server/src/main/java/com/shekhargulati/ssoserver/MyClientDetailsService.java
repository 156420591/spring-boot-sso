package com.shekhargulati.ssoserver;

import java.util.Arrays;

import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Component;

@Component
public class MyClientDetailsService implements ClientDetailsService {

	String appleDoSha256 = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b";
	String passwordDoSha256 = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";

	String sha256_bar = "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9";
	//echo -ne client1 |sha256sum
	String sha256_client1 = "1917e33407c28366c8e3b975b17e7374589312676b90229adb4ce6e58552e223";
	String sha256_client2 = "3f455143e75d1e7fd659dea57023496da3bd9f2f8908d1e2ac32641cd819d3e3";

	@Override
	public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
		BaseClientDetails result = new BaseClientDetails();
		System.out.println("===========================" + clientId);

		String passwordFromDb;
		if("foo".equals(clientId)) {
			passwordFromDb = sha256_bar;
			result.setRefreshTokenValiditySeconds(60);
			result.setAccessTokenValiditySeconds(60);
			result.setAuthorizedGrantTypes(Arrays.asList("authorization_code", "refresh_token", "password", "client_credentials"));

		}else if("client1".equals(clientId)) {
			passwordFromDb = sha256_client1;
			result.setRefreshTokenValiditySeconds(60*2);
			result.setAccessTokenValiditySeconds(60*2);
			result.setAuthorizedGrantTypes(Arrays.asList("authorization_code", "refresh_token", "password", "client_credentials"));

		}else if("client2".equals(clientId)) {
			passwordFromDb = sha256_client2;
			result.setRefreshTokenValiditySeconds(60*3);
			result.setAccessTokenValiditySeconds(60*3);
			result.setAuthorizedGrantTypes(Arrays.asList("authorization_code", "refresh_token", "password", "client_credentials"));

		}else {
			throw new ClientRegistrationException("client not exist");
		}
		//here must set client id, or can't find the client id at all
		result.setClientId(clientId);
		result.setClientSecret(passwordFromDb);
		result.setScope(Arrays.asList("all"));

		return result;
	}
}
