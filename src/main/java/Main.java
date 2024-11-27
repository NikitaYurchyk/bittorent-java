import com.dampcake.bencode.Type;
import com.google.gson.Gson;
import com.dampcake.bencode.Bencode;

import java.util.List;
import java.util.Map;
import java.util.Objects;

public class Main {
  private static final Gson gson = new Gson();

  public static void main(String[] args) throws Exception {
    
    String command = args[0];
    if("decode".equals(command)) {
        String bencodedValue = args[1];
        String decoded;
        try {
          decoded = decodeBencode(bencodedValue);
        } catch(RuntimeException e) {
          System.out.println(e.getMessage());
          return;
        }
        System.out.println(decoded);
    } else {
      System.out.println("Unknown command: " + command);
    }

  }

  static String decodeBencode(String bencodedString) {

    if (Character.isDigit(bencodedString.charAt(0))) {
      int firstColonIndex = 0;
      for(int i = 0; i < bencodedString.length(); i++) { 
        if(bencodedString.charAt(i) == ':') {
          firstColonIndex = i;
          break;
        }
      }
      int length = Integer.parseInt(bencodedString.substring(0, firstColonIndex));
      return gson.toJson(bencodedString.substring(firstColonIndex+1, firstColonIndex+1+length));
    }
    if (Character.isLetter(bencodedString.charAt(0))){
      if(bencodedString.charAt(0) == 'i') {
        Bencode bencode = new Bencode();
        Long number = bencode.decode(bencodedString.getBytes(), Type.NUMBER);
        return gson.toJson(number);
      }
      if(bencodedString.charAt(0) == 'l') {
        Bencode bencode = new Bencode();
        List<Object> lst = bencode.decode(bencodedString.getBytes(), Type.LIST);
        return gson.toJson(lst);
      }
      if(bencodedString.charAt(0) == 'd') {
        Bencode bencode = new Bencode();
        Map<String, Object> dict = bencode.decode(bencodedString.getBytes(), Type.DICTIONARY);
        return gson.toJson(dict);
      }
    }

    else {
      throw new RuntimeException("Only strings are supported at the moment");
    }
    return null;
  }
  
}
