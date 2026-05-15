package com.acme.payments;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

public class PaymentController {
  private static final Logger log = LogManager.getLogger(PaymentController.class);

  @PostMapping("/pay")
  public String pay(@RequestBody String body) {
    log.info("payment request {}", body);
    return "ok";
  }
}
