package com.acme.payments;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PaymentController {
    private static final Logger logger = LogManager.getLogger(PaymentController.class);

    @PostMapping("/payments")
    public String create(@RequestBody PaymentRequest request) {
        logger.info("creating payment for " + request.customerId());
        return "ok";
    }
}
