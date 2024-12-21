import com.dampcake.bencode.Type;
import com.google.gson.Gson;
import com.dampcake.bencode.Bencode;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class Main {
  private static final Gson gson = new Gson();
  private static String getInfo(Object j){
    StringBuilder result = new StringBuilder();
    result.append('d');
    if(j instanceof Map<?,?>) {
      for (Map.Entry<String, Object> i : ((Map<String, Object>) j).entrySet()) {
        String key = i.getKey();
        Object val = i.getValue();
        if(val instanceof Integer){
          result.append(key.length()+':' + key + 'i' + ((Integer) val).intValue() + 'e');
        } else if (val instanceof String) {
          result.append(key.length() + ':' + key + ((String) val).length() + ':' + val);
        }
      }
    }
    return result.toString();
  }
  private static String strToSHA1(byte[] info){
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      byte[] hashBytes = md.digest(info);
      StringBuilder res = new StringBuilder();
      for (byte b : hashBytes) {
        res.append(String.format("%02x", b));
      }
      return res.toString();
    }catch (NoSuchAlgorithmException e){
      throw new RuntimeException("SHA-1 Algorithm not found", e);
    }
  }


  private static byte[] getInfoBytes(byte[] bytes){
    byte[] pattern = "4:info".getBytes(StandardCharsets.UTF_8);
    int index = -1;
    for(int i = 0; i < bytes.length; i++){
      if(pattern[0] == bytes[i] && bytes.length - i + 1 >= pattern.length){
        Boolean isMatch = true;
        for(int j = i; j < pattern.length; j++){
          if(pattern[j] != bytes[i + j]){
            isMatch = false;
            break;
          }
        }
        index = isMatch ? i + pattern.length: -1;
        if(index > -1){
          break;
        }
      }
    }

    byte[] res = new byte[bytes.length - index];
    int ind = 0;
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    for(int i = index; i < bytes.length; i++){
      res[ind] = bytes[i];
      ind++;
    }
    return res;
  }

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
    }else if("info".equals(command)) {
      String fileName = args[1];
      try {
        byte[] bytes = Files.readAllBytes(Paths.get(fileName));
        Bencode bencode = new Bencode(true);

        Map<String, Object> f = bencode.decode(bytes, Type.DICTIONARY);
        Object announceObject = f.get("announce");

        byte[] announceBytes = ((ByteBuffer) announceObject).array();
        var trackerURL = new String(announceBytes, StandardCharsets.UTF_8);

        Map<String, Object> info = (Map<String, Object>) f.get("info");

        System.out.println(gson.toJson("Tracker URL: "+ trackerURL));
        System.out.println(gson.toJson("Length: "+ info.get("length")));
        System.out.println("Info Hash: "+ strToSHA1(bencode.encode(info)));

      }catch (RuntimeException e) {
        System.err.println(e.getMessage());
      }


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
