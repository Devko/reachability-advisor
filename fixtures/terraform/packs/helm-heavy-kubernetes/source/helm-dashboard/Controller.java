import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

class Controller {
  private static final Logger logger = LogManager.getLogger(Controller.class);

  @GetMapping("/search")
  String search(@RequestParam String q) {
    logger.error(q);
    return "ok";
  }
}
