import javax.crypto.Cipher;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

class RawRsa {
    void positive(KeyGenParameterSpec.Builder b) throws Exception {
        Cipher a = Cipher.getInstance("RSA/ECB/NoPadding"); // EXPECT:raw-rsa-java-nopadding-cipher
        Cipher c = Cipher.getInstance("RSA/NONE/NoPadding"); // EXPECT:raw-rsa-java-nopadding-cipher
        b.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE); // EXPECT:raw-rsa-android-keystore-padding-none
    }
    void negative(KeyGenParameterSpec.Builder b) throws Exception {
        Cipher d = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        Cipher e = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        Cipher f = Cipher.getInstance("AES/CBC/NoPadding");
        b.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP);
    }
}
