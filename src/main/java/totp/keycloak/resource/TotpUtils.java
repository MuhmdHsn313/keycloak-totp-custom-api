package totp.keycloak.resource;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.keycloak.common.util.Base64;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.Base32;
import org.keycloak.models.utils.HmacOTP;

import java.io.ByteArrayOutputStream;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class TotpUtils {

    public static String encode(String totpSecret) {
        String encoded = Base32.encode(totpSecret.getBytes());
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < encoded.length(); i += 4) {
            sb.append(encoded.substring(i, i + 4 < encoded.length() ? i + 4 : encoded.length()));
            if (i + 4 < encoded.length()) {
                sb.append(" ");
            }
        }
        return sb.toString();
    }


    public static String qrCode(String totpSecret, RealmModel realm, UserModel user) {
        try {
            String keyUri = realm.getOTPPolicy().getKeyURI(realm, user, totpSecret);

            int width = 246;
            int height = 246;

            QRCodeWriter writer = new QRCodeWriter();
            final BitMatrix bitMatrix = writer.encode(keyUri, BarcodeFormat.QR_CODE, width, height);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "png", bos);
            bos.close();

            return Base64.encodeBytes(bos.toByteArray());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}