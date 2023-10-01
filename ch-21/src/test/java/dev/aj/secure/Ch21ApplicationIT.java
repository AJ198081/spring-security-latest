package dev.aj.secure;

import dev.aj.secure.controllers.DemoController;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;

@SpringBootTest
@AutoConfigureMockMvc
public class Ch21ApplicationIT {

    @Autowired
    private ApplicationContext context;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void testContextLoads() {
        Assertions.assertDoesNotThrow(() -> context.getBean(DemoController.class));

    }

    @Test
    void testGetDemoController() throws Exception {

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/api/secure/{name}", "Amarjit")
                                                                    .with(httpBasic("AJ", "password")))
                                     .andExpect(MockMvcResultMatchers.status().isOk())
                                     .andExpect(MockMvcResultMatchers.content().string("Hello Amarjit."))
                                     .andReturn();

        System.out.println(mvcResult.getResponse());
    }

    @Test
    void testPostDemoController() throws Exception {

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.post("/api/secure/{name}", "Amarjit")
                                                                    .with(httpBasic("AJ", "password"))
                                                                    .with(SecurityMockMvcRequestPostProcessors.csrf()))
                                     .andExpect(MockMvcResultMatchers.status()
                                                                     .isOk())
                                     .andExpect(MockMvcResultMatchers.content()
                                                                     .string("Hello Amarjit."))
                                     .andReturn();

        System.out.println(mvcResult.getResponse());
    }
}
