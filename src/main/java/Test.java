import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;

public class Test {

    public static void main(String[] args) throws MalformedURLException, URISyntaxException {
        URL url = new URL("http://localhost:8080/login?p1=Test");
        System.out.println(url.toString());
        System.out.println(url.toExternalForm());
        System.out.println(url.getPath() + "?" + url.getQuery());
    }

}