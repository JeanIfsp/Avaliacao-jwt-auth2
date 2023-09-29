package br.edu.ifsp.arq.dw2s6.ea2.security;


import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import br.edu.ifsp.arq.dw2s6.ea2.domain.model.User;
import br.edu.ifsp.arq.dw2s6.ea2.repository.UserRepository;

@Service
public class AppUserDetailsService implements UserDetailsService {

  @Autowired
  private UserRepository usuarioRepository;
  
  @Override
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    Optional<User> usuarioOptional = usuarioRepository.findByEmail(email);
    User usuario = usuarioOptional
        .orElseThrow(() -> 
        new UsernameNotFoundException("Usuário e/ou senha incorretos"));
    return new org.springframework.security.core.userdetails.User(email, usuario.getPassword(), getPermissoes(usuario));
  }

  private Collection<? extends GrantedAuthority> getPermissoes(User usuario) {
    Set<SimpleGrantedAuthority> authorities = new HashSet<>();
    usuario.getPermissions().forEach(
        p -> authorities.add(
            new SimpleGrantedAuthority(p.getDescription().toUpperCase())));
    return authorities;
  }

}