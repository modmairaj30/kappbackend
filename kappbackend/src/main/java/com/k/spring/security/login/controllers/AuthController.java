package com.k.spring.security.login.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.k.spring.security.constant.CommonConstant;
import com.k.spring.security.login.models.ERole;
import com.k.spring.security.login.models.Role;
import com.k.spring.security.login.models.User;
import com.k.spring.security.login.payload.request.LoginRequest;
import com.k.spring.security.login.payload.request.SignupRequest;
import com.k.spring.security.login.payload.response.UserInfoResponse;
import com.k.spring.security.login.payload.response.MessageResponse;
import com.k.spring.security.login.repository.RoleRepository;
import com.k.spring.security.login.repository.UserRepository;
import com.k.spring.security.login.security.jwt.JwtUtils;
import com.k.spring.security.login.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
//for Angular Client (withCredentials)
//@CrossOrigin(origins = "http://localhost:8081", maxAge = 3600, allowCredentials="true")
@RestController
@RequestMapping("/api/auth")
public class AuthController {
 
  AuthenticationManager authenticationManager;

  UserRepository userRepository;

  RoleRepository roleRepository;

  PasswordEncoder encoder;

  JwtUtils jwtUtils;
  
  @Autowired
  public AuthController(AuthenticationManager authenticationManager, UserRepository userRepository,RoleRepository roleRepository, PasswordEncoder encoder,JwtUtils jwtUtils){
  this.authenticationManager = authenticationManager;
  this.userRepository = userRepository;
  this.roleRepository = roleRepository;
  this.encoder = encoder;
  this.jwtUtils = jwtUtils;
  }

  @PostMapping("/signin")
  public ResponseEntity<UserInfoResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager
        .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);

    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

    ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

    List<String> roles = userDetails.getAuthorities().stream()
        .map(item -> item.getAuthority())
        .collect(Collectors.toList());

    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
        .body(new UserInfoResponse(userDetails.getId(),
                                   userDetails.getUsername(),
                                   userDetails.getEmail(),
                                   roles));
  }

  @PostMapping("/signup")
  public ResponseEntity<MessageResponse> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity.badRequest().body(new MessageResponse(CommonConstant.ERROR_USERNAME_ALREADY_TAKEN));
    }

    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return ResponseEntity.badRequest().body(new MessageResponse(CommonConstant.ERROR_EMAIL_ALREADY_INUSE));
    }

    // Create new user's account
    User user = new User(signUpRequest.getUsername(),
                         signUpRequest.getEmail(),
                         encoder.encode(signUpRequest.getPassword()));

    Set<String> strRoles = signUpRequest.getRole();
    Set<Role> roles = new HashSet<>();

    if (strRoles == null) {
      Role userRole = roleRepository.findByName(ERole.ROLE_USER)
          .orElseThrow(() -> new RuntimeException(CommonConstant.ERROR_ROLE));
      roles.add(userRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
        case "admin":
          Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
              .orElseThrow(() -> new RuntimeException(CommonConstant.ERROR_ROLE));
          roles.add(adminRole);

          break;
        case "mod":
          Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
              .orElseThrow(() -> new RuntimeException(CommonConstant.ERROR_ROLE));
          roles.add(modRole);

          break;
        default:
          Role userRole = roleRepository.findByName(ERole.ROLE_USER)
              .orElseThrow(() -> new RuntimeException(CommonConstant.ERROR_ROLE));
          roles.add(userRole);
        }
      });
    }

    user.setRoles(roles);
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse(CommonConstant.USER_REGISTERED));
  }

  @PostMapping("/signout")
  public ResponseEntity<MessageResponse> logoutUser() {
    ResponseCookie cookie = jwtUtils.getCleanJwtCookie();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
        .body(new MessageResponse(CommonConstant.SIGN_OUT));
  }
  
  

  
}
