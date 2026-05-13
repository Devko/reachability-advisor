package example;

import java.nio.file.Path;
import java.nio.file.Paths;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

class UploadController {
    @PostMapping("/upload")
    void upload(@RequestParam MultipartFile archive) throws Exception {
        Path output = Paths.get("/tmp/extract");
        try (ZipArchiveInputStream zip = new ZipArchiveInputStream(archive.getInputStream())) {
            ZipArchiveEntry entry = zip.getNextZipEntry();
            if (entry != null) {
                output.resolve(entry.getName()).normalize();
            }
        }
    }
}
