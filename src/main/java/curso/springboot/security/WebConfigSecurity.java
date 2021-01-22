package curso.springboot.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebConfigSecurity extends WebSecurityConfigurerAdapter {

	@Autowired
	private ImplementacaoUserDetailsService implementacaoUserDetailsService;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().authorizeRequests()
				.antMatchers(HttpMethod.GET, "/").permitAll()
				.antMatchers(HttpMethod.GET,"/meu_css/**", "/meu_js/**", "/materialize/**").permitAll()
				.antMatchers(HttpMethod.GET, "/cadastropessoa").hasAnyRole("ADMIN").anyRequest().authenticated().and()
				.formLogin().permitAll().loginPage("/login").defaultSuccessUrl("/cadastropessoa")
				.failureUrl("/login?error=true").and().logout().logoutSuccessUrl("/login")
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {

		auth.userDetailsService(implementacaoUserDetailsService).passwordEncoder(new BCryptPasswordEncoder());

//		auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
//		.withUser("alex")
//		.password("$2a$10$Sjigit9J0CexqySKU/Z0vOA4uz/w61f5Yq6V4.DfFK0BUkbBByTHq")
//		.roles("ADMIN");
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/materialize/**");
	}

}
