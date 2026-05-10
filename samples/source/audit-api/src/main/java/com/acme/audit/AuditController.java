package com.acme.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuditController {
    private final ObjectMapper mapper = new ObjectMapper();

    @PostMapping("/audit")
    public String audit(@RequestBody String payload) throws Exception {
        Object event = mapper.readValue(payload, Object.class);
        return mapper.writeValueAsString(event);
    }
}
