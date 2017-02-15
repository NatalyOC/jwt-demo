package nl.blueshift;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.constraints.NotNull;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
public class JwtDemoApplication {

    private static final String SECRET = "SecretOnlyTheServerKnows";

    private Map<String, String> users = new HashMap<>();

    private Map<String, String> roles = new HashMap<>();

    public JwtDemoApplication() {
        users.put("Alexander","ASDFJKL");
        users.put("John","Welcome123");
        users.put("Victoria","VictoriasSecret");

        roles.put("Alexander", "Admin");
        roles.put("John", "Editor");
        roles.put("Victoria", "Member");
    }

	@RequestMapping(value = "/username/{username}/password/{password}", method = RequestMethod.GET, produces = MediaType.TEXT_PLAIN_VALUE)
    @ResponseBody
	public ResponseEntity login(@PathVariable("username") @NotNull String username,
                                @PathVariable("password") @NotNull String password) {

        if(password.equals(users.get(username))) {
            HttpHeaders headers = new HttpHeaders();
            try {
                String jwtToken = JWT.create().withSubject(username).sign(Algorithm.HMAC256(SECRET));
                headers.add("Set-Cookie","jwtToken="+jwtToken);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            return new ResponseEntity<String>(headers,HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
	}

    @RequestMapping(value = "/myrole", method = RequestMethod.GET, produces = MediaType.TEXT_PLAIN_VALUE)
    @ResponseBody
	public ResponseEntity myRole(@CookieValue("jwtToken") String jtwToken) {
        try {
            JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET)).build();
            DecodedJWT jwt = verifier.verify(jtwToken);
            return new ResponseEntity<>(roles.get(jwt.getSubject()), HttpStatus.OK);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }

	public static void main(String[] args) {
		SpringApplication.run(JwtDemoApplication.class, args);
	}
}
