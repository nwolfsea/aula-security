package br.com.zup.aula.Security.configuracoes;

import br.com.zup.aula.Security.JWT.ComponenteJWT;
import br.com.zup.aula.Security.JWT.FiltroDeAutenticacaoJwt;
import br.com.zup.aula.Security.JWT.FiltroDeAutorizacao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class ConfiguracaoSeguranca extends WebSecurityConfigurerAdapter {

    @Autowired
    private ComponenteJWT componenteJWT;
    @Autowired
    private UserDetailsService userDetailsService;

    private static final String[] PUBLIC_MATCHERS_GET = {

    };

    private static final String[] PUBLIC_MATCHERS_POST = {
            "/usuarios/",
    };

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.cors();

        http.authorizeRequests().antMatchers(HttpMethod.GET, PUBLIC_MATCHERS_GET).permitAll()
                .antMatchers(HttpMethod.POST, PUBLIC_MATCHERS_POST).permitAll()
                .anyRequest().authenticated();
        http.addFilter(new FiltroDeAutenticacaoJwt(componenteJWT, authenticationManager()));
        http.addFilter(new FiltroDeAutorizacao(authenticationManager(), componenteJWT, userDetailsService));
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
    }

    @Bean
    BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Bean
    CorsConfigurationSource configuracaoDeCors(){
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
        return source;
    }


}
