package detection;

public class diffSitesTest {


    diffSites resultdiffs = new diffSites();

    String response_one = "HTTP/1.1 200 \n Content-Type: text/html;charset=UTF-8\n + Date: Tue, 03 Dec 2019 08:54:53 GMT\n +Connection: close\n + Content-Length: 11196\n +\n +\n +\n +\n";

    String response_two = "HTTP/1.1 200 \n Content-Type: text/html;charset=UTF-8\n + Date: Tue, 03 Dec 2019 08:54:53 GMT\n +Connection: close\n + Content-Length: 4589\n +\n +\n +\n +\n";




    String response_three = "HTTP/1.1 200 \n" +
            "Content-Type: text/html;charset=UTF-8\n" +
            "Date: Tue, 03 Dec 2019 08:54:53 GMT\n" +
            "Connection: open\n" +
            "Content-Length: 452297\n" +
            "\n" +
            "\n" +
            "\n" +
            "\n";

    String response_four = "HTTP/1.1 200 \n Content-Type: text/html;charset=UTF-8\n + Date: Tue, 03 Dec 2019 08:54:53 GMT\n +Connection: close\n + Content-Length: 11196\n +\n +\n +\n +\n";


    public void testResponseDifferences ( ){


    resultdiffs.diffResponses(response_one, response_two, response_four);
}
}
