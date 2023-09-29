package br.edu.ifsp.arq.dw2s6.ea2.resource;

import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import br.edu.ifsp.arq.dw2s6.ea2.domain.model.Tag;
import br.edu.ifsp.arq.dw2s6.ea2.repository.TagRepository;
import br.edu.ifsp.arq.dw2s6.ea2.service.TagService;

@RestController
@RequestMapping("/tags")
public class TagResource {
	@Autowired
	private TagRepository tagRepository;
	
	@Autowired
	private TagService tagService;
	
	@PreAuthorize("hasAuthority('ROLE_SEARCH_ACTIVITY') and #oauth2.hasScope('read')")
	@GetMapping
	public List<Tag> list(){
		return tagRepository.findAll();
	}
	
	@PostMapping
	@PreAuthorize("hasAuthority('ROLE_REGISTER_ACTIVITY') and #oauth2.hasScope('write')")
	@ResponseStatus(HttpStatus.CREATED)
	public Tag create(@Valid @RequestBody Tag tag, HttpServletResponse response) {
		return tagRepository.save(tag);
	}
	@PreAuthorize("hasAuthority('ROLE_SEARCH_ACTIVITY') and #oauth2.hasScope('read')")
	@GetMapping("/{id}")
	public ResponseEntity<Tag> findById(@PathVariable Long id){
		Optional<Tag> tag = tagRepository.findById(id);
		if(tag.isPresent()) {
			return ResponseEntity.ok(tag.get());
		}
		return ResponseEntity.notFound().build();
	}
	
	@DeleteMapping("/{id}")
	@PreAuthorize("hasAuthority('ROLE_REMOVE_ACTIVITY') and #oauth2.hasScope('write')")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void remove(@PathVariable Long id) {
		tagRepository.deleteById(id);
	}
	
	@PutMapping("/{id}")
	@PreAuthorize("hasAuthority('ROLE_REMOVE_ACTIVITY') and #oauth2.hasScope('write')")
	public ResponseEntity<Tag> update(@PathVariable Long id, @Valid @RequestBody Tag tag) {
		Tag tagSaved = tagService.update(id, tag);
		return ResponseEntity.ok(tagSaved);
	}
}
