package dev.aj;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;


@SpringBootTest
public class Ch19ApplicationTest {

    @Autowired
    ApplicationContext applicationContext;

    @Test
    void loadsContext() {
        Assertions.assertDoesNotThrow(() -> applicationContext.getBean(Ch19Application.class));
    }

}
