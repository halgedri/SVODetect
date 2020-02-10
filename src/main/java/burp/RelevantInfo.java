package burp;

import java.util.ArrayList;
import java.util.List;

public class RelevantInfo {


        List<String> importantAttributesList = new ArrayList<>();


        public List<String> getImportantAttributesList(){

            importantAttributesList.add("status_code");
            importantAttributesList.add("page_title");
            importantAttributesList.add("visible_text");
            importantAttributesList.add("location");
            importantAttributesList.add("whole_body_content");
            importantAttributesList.add("word_count");
            importantAttributesList.add("content_length");
            importantAttributesList.add("visible_word_count");
            importantAttributesList.add("input_submit_labels");
            importantAttributesList.add("content_location");

            return importantAttributesList;
        }

    }


