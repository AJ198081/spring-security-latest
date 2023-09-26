package dev.aj;

import dev.aj.domain.entities.Authority;
import dev.aj.domain.entities.User;
import dev.aj.repositories.UserRepository;
import jakarta.annotation.PostConstruct;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@RequiredArgsConstructor
public class Ch02Application {

    private final UserRepository userRepository;

    public static void main(String[] args) {

        SpringApplication.run(Ch02Application.class,
                              args);
    }

    @PostConstruct
    void loadUser() {
        Authority read = Authority.builder()
                                  .name("read")
                                  .build();
        User aj = User.builder()
                         .username("aj")
                         .password("password")
                         .build();

        aj.addAuthority(read);


        Authority read1 = Authority.builder()
                                  .name("read")
                                  .build();

        aj.addAuthority(read1);

        User dj = User.builder()
                      .username("dj")
                      .password("password")
                      .build();

        dj.addAuthority(read);
        dj.addAuthority(read1);

        userRepository.saveAll(List.of(aj,
                                       dj));


    }
}