package detection;

import burp.IExtensionHelpers;

import static jdk.nashorn.internal.objects.ArrayBufferView.length;

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
    //


    String response_one;
    String response_two;


    public double diffResponses(String response_one, String response_two){

        String[] responseOneArray = response_one.split(" ");
        String[] responseTwoArray = response_two.split(" ");

        int lengthResponseOne = responseOneArray.length;

        for (int i = 0; i <lengthResponseOne; i++){

        }


        double resultDiffResponses = 0.0;

        return resultDiffResponses;

    }










}
