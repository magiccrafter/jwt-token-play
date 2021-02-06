import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.Writer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;

class JwtPKSigningExample {

    public static void main(String[] args) throws Exception {
        Map<String, Object> keys = generateRSAKeys();

        FileOutputStream fos1 = new FileOutputStream("privateKey");
        fos1.write(((RSAPrivateKey) keys.get("private")).getEncoded());
        fos1.close();

        Base64.Encoder encoder = Base64.getEncoder();

        Writer out = new FileWriter("private.key");
        out.write("-----BEGIN RSA PRIVATE KEY-----\n");
        out.write(encoder.encodeToString(((RSAPrivateKey) keys.get("private")).getEncoded()));
        out.write("\n-----END RSA PRIVATE KEY-----\n");
        out.close();

        FileOutputStream fos2 = new FileOutputStream("publicKey");
        fos2.write(((RSAPublicKey) keys.get("public")).getEncoded());
        fos2.close();

        out = new FileWriter("public.pub");
        out.write("-----BEGIN RSA PUBLIC KEY-----\n");
        out.write(encoder.encodeToString(((RSAPublicKey) keys.get("public")).getEncoded()));
        out.write("\n-----END RSA PUBLIC KEY-----\n");
        out.close();

        String token = null;
        try {
            RSAPrivateKey privateKey = (RSAPrivateKey) keys.get("private");
            Algorithm algorithm = Algorithm.RSA256(null, privateKey);
            token = JWT.create()
                    .withIssuer("pk-signing-example")
                    .sign(algorithm);
        } catch (JWTCreationException x) {
            throw x;
        }

        try {
            RSAPublicKey publicKey = (RSAPublicKey) keys.get("public");
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("pk-signing-example")
                    .build();
            DecodedJWT jwt = verifier.verify(token);

            System.out.println(jwt.getToken());
        } catch (JWTVerificationException x) {
            throw x;
        }
    }

    private static Map<String, Object> generateRSAKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return Map.of("private", keyPair.getPrivate(), "public", keyPair.getPublic());
    }
}