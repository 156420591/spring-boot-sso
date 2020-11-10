package com.shekhargulati.ssoserver;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

public class MyUserDetailService implements UserDetailsService {
//	@Autowired
//	PasswordEncoder passwordEncoder;

	String appleDoMd5 = "1f3870be274f6c49b3e31a0c6728957f";
	String appleDoSha256 = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b";

	String pearDoSha256 = "97cfbe87531abe0c6bac7b21d616cb422faaa158a9f2ae7e8685c79eb85fc65e";
	String passwordDoSha256 = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		String passwordLoadFromExternal;
		UserDetails udResult;
		List<SimpleGrantedAuthority> lstGrant = new ArrayList<>();
		if("user".equals(username)) {
			passwordLoadFromExternal = this.passwordDoSha256;
			udResult = User.withUsername(username).password(passwordLoadFromExternal).roles("USER").build();
//			lstGrant.add(new SimpleGrantedAuthority("USER"));

		}else if("apple".equals(username)) {
			passwordLoadFromExternal = this.appleDoSha256;
			udResult = User.withUsername(username).password(passwordLoadFromExternal).roles("APPLE").build();
//			lstGrant.add(new SimpleGrantedAuthority("APPLE"));

		}else if("pear".equals(username)) {
			passwordLoadFromExternal = this.pearDoSha256;
			udResult = User.withUsername(username).password(passwordLoadFromExternal).roles("PEAR").build();
//			lstGrant.add(new SimpleGrantedAuthority("PEAR"));

		}else {
			throw new UsernameNotFoundException("user not exist");
		}

		return udResult;
	}

}
