package curso.springboot.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import curso.springboot.model.Usuario;
import curso.springboot.repository.UsuarioRepository;

@Service
public class ImplementacaoUserDetailsService implements UserDetailsService{
	
	@Autowired
	private UsuarioRepository usuarioRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		Usuario usuario = usuarioRepository.findUserByLogin(username);
		
		if(username == null) {
			throw new UsernameNotFoundException("Usuário não foi encontrado!");
		}
		
		return new User(usuario.getLogin(), usuario.getPassword(), 
				usuario.isEnabled(), true, 
				true, true, usuario.getAuthorities());
	}

}