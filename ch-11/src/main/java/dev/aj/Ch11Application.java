package dev.aj;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@Slf4j
public class Ch11Application implements ApplicationRunner {
    public static void main(String[] args) {
        SpringApplication.run(dev.aj.Ch11Application.class, args);
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        byte [] code = new byte[32];
        secureRandom.nextBytes(code);
        String codeVerifier = Base64.getUrlEncoder()
                                    .withoutPadding()
                                    .encodeToString(code);

        log.info("Code Verifier: {}", codeVerifier);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

        byte [] digested = messageDigest.digest(codeVerifier.getBytes());
        String codeChallenge = Base64.getUrlEncoder()
                                     .withoutPadding()
                                     .encodeToString(digested);

        log.info("Code Challenge: {}", codeChallenge);
    }
}