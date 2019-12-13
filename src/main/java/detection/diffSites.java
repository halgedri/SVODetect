package detection;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

public class diffSites {


    //load the website, and if they differentiate set variable on true
    //compares the input files
    // if inputHeader1 != inputHeader2 == effect = true in the matrix for this input parameter
    //is_different()
    // webseite_original und webseite_secondtry
    // Headers ohne Zeitstempel speichern
    // banned_headers = ['expires' ,  -...] Header wird in einem Array gespeichert


    // mit ner loop durch das Array laufen und vergleichen

    // compare the differences in the response of two Responses and load into new Matrix/Array
    // JUST RESPONSE HEADERS


    //siehe scan.java

    String response_one;
    String response_two;

    public int diffResponses(String response_one, String response_two, String response_four){

        String[] responseOneArray = response_one.split("\n");
        String[] responseTwoArray = response_two.split("\n");

        int lengthResponseOne = responseOneArray.length;

        int diffCounter = 0;


        for (int i = 0; i <lengthResponseOne; i++){

            if (responseOneArray[i].compareTo(responseTwoArray[i]) == -3) { //12
                diffCounter++;
            }
        }
        System.out.println("There are " + diffCounter +" differences in the Response Files");

        int resultDiffResponses = diffCounter;

        return resultDiffResponses;
    }



    public boolean isHeaderDifferent(IHttpRequestResponse response_original, IHttpRequestResponse response_reloaded) {
        //load headers into array

        return true;
    }
}
