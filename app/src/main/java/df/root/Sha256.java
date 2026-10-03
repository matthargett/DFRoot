package df.root;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Locale;

final class Sha256 {
    private Sha256() {}

    static String file(File file) throws Exception {
        try (InputStream input = new FileInputStream(file)) {
            return stream(input);
        }
    }

    static String stream(InputStream input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[8192];
        for (int count; (count = input.read(buffer)) != -1; )
            digest.update(buffer, 0, count);
        StringBuilder hex = new StringBuilder(64);
        for (byte value : digest.digest())
            hex.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        return hex.toString();
    }
}
