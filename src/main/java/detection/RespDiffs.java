package detection;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class RespDiffs {



  /*  public  Map < URL, Boolean> baseScanRespDiff(HashMap scanResponseMap, HashMap baseResponseMap){

        int lengthBaseResponseMap = baseResponseMap.size();

        Map < URL, Boolean> responseDiffMap = areEqualKeyValues(scanResponseMap, baseResponseMap);

        return responseDiffMap;
    }*/

    public Map <URL, Boolean> areEqualKeyValues (Map <URL, byte[]> first,Map <URL, byte[]> second) {

        Map<URL, Boolean> baseScanDiffMap = new HashMap<>();


        //NullPointer!

        if (!(first.entrySet().contains(null)) || !(second.entrySet().contains(null))) {
            if (!(first.keySet().contains(null)) || !(second.keySet().contains(null))) {


                return null;

            }
            else {
                return null;

            }

        } else {
            baseScanDiffMap = first.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().equals(second.get(e.getKey()))));
            //return baseScanDiffMap;
            return null;
        }

        //  Map <Integer, Boolean> collect = list.stream().collect(HashMap::new, (m,v)->m.put(v.getKey, v.getValue(), HashMap::putAll));
    }

}
