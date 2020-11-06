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
	@Autowired
	PasswordEncoder passwordEncoder;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		String passwordLoadFromExternal;
		List<SimpleGrantedAuthority> lstGrant = new ArrayList<>();
		if("user".equals(username)) {
			passwordLoadFromExternal = this.passwordEncoder.encode("password");
			lstGrant.add(new SimpleGrantedAuthority("USER"));
		}else if("apple".equals(username)) {
			passwordLoadFromExternal = this.passwordEncoder.encode("apple");
			lstGrant.add(new SimpleGrantedAuthority("APPLE"));
		}else {
			throw new UsernameNotFoundException("user not exist");
		}
		return new User(username, passwordLoadFromExternal, lstGrant);
	}

}
