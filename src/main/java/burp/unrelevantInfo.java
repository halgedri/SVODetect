package burp;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class unrelevantInfo {


    //TODO
    // Informationen bzw. Responses in Strings speichern und aufsplitten, und relevante und unrelevaten Informationen aufsplitten

    //TODO Try this Method
    public static String CropHeaders(String s1) {
        int i = s1.indexOf("\r\n\r\n");
        if (i == -1) {
            i = 0;
        }
        return s1.substring(i);
    }

    public List<String> deleteUnrelevantInfo(byte[] scanResponseList, byte[] baseResponseList) {




        // getSimilarities:
        //responses splitten bei jedem leerzeichen .split(" ")

        List <String> scanResponseList2 = new ArrayList<>();


        Iterator <String> irt2 = scanResponseList2.iterator();


        //Unrelevant: Cookie, Expires, Date, ETag,


        // Important: HTTP 200, Content-Type, Content-Lenght, Accrept- Ranges
        //


        return null;
    }


}

