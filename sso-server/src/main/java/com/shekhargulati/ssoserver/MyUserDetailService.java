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

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		String passwordLoadFromExternal;
		List<SimpleGrantedAuthority> lstGrant = new ArrayList<>();
		if("user".equals(username)) {
			passwordLoadFromExternal = this.appleDoMd5;
			lstGrant.add(new SimpleGrantedAuthority("USER"));

		}else if("apple".equals(username)) {
			passwordLoadFromExternal = this.appleDoSha256;
			lstGrant.add(new SimpleGrantedAuthority("APPLE"));

		}else {
			throw new UsernameNotFoundException("user not exist");
		}

		return new User(username, passwordLoadFromExternal, lstGrant);
	}

}
