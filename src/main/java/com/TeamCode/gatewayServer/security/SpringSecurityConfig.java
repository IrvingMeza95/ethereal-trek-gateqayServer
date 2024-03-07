package com.TeamCode.gatewayServer.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@EnableWebFluxSecurity
public class SpringSecurityConfig {
	
	@Autowired
	private JwtAuthenticationFilter authenticationFilter;

	@Bean
	public SecurityWebFilterChain configure(ServerHttpSecurity http) {
		return http.authorizeExchange()
				.pathMatchers("/api/security/oauth/**", "/api/usuarios/extras/**").permitAll()
				.pathMatchers(HttpMethod.GET, "/api/services/servicios/listar",
						"/api/services/paquetes/listar"
						).permitAll()
				.pathMatchers(HttpMethod.GET, "/api/usuarios/clientes/{param}",
						"/api/usuarios/empleados/{param}").hasAnyRole("ADMIN", "USER")
				.pathMatchers("/api/usuarios/**", "/api/auth/**").hasRole("ADMIN")
				.anyExchange().authenticated()
				.and().addFilterAt(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
				.csrf().disable()
				.build();
	}
	
}
