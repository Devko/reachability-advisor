package example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

public class LogController {
  private static final Logger logger = LogManager.getLogger(LogController.class);

  @GetMapping("/log")
  public String log(@RequestParam String value) {
    logger.error(value);
    return "ok";
  }

  @GetMapping("/proxy")
  public String proxy(@RequestParam String url) {
    return new RestTemplate().getForObject(url, String.class);
  }
}
