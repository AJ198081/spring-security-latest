package dev.aj.simple.controllers;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;

@SpringBootTest
@AutoConfigureMockMvc
class DemoControllerTest {

    @Autowired
    private MockMvc mockMvc;

    // Have two different methodologies in this class, first one for OAuth2-Resource-Server, 2nd for 'http basic'

    @Test
    void getDemo() throws Exception {

        mockMvc.perform(MockMvcRequestBuilders.get("/api/secure/{name}", "AJ")
//                                              .with(jwt().authorities(new SimpleGrantedAuthority("admin")))
                                              .with(jwt().jwt(Jwt.withTokenValue("abc")
                                                                 .header("alg", "s32")
                                                                 .claim("user", "admin")
                                                                 .build())))
               .andExpect(MockMvcResultMatchers.status()
                                               .isOk())
               .andExpect(MockMvcResultMatchers.content()
                                               .string("Hello AJ"));
    }

    @Test
    @WithMockUser(authorities = "read")
    void postDemo() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/api/secure/{name}", "AJ")
                                              .with(csrf()))
               .andExpect(MockMvcResultMatchers.status()
                                               .isOk())
               .andExpect(MockMvcResultMatchers.content()
                                               .string("Hello AJ"));
    }
}