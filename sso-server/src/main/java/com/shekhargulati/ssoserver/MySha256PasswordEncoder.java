package com.shekhargulati.ssoserver;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.xml.bind.DatatypeConverter;

import org.springframework.security.crypto.password.PasswordEncoder;

public class MySha256PasswordEncoder implements PasswordEncoder {

	@Override
	public String encode(CharSequence rawPassword) {
		String result = "";
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] byresult = digest.digest(rawPassword.toString().getBytes());
			result = DatatypeConverter.printHexBinary(byresult);
		} catch (Exception e) {
		}

		return result;
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		String myencoded = this.encode(rawPassword);
		if(myencoded.equalsIgnoreCase(encodedPassword)) {
			return true;
		}
		return false;
	}


}
