import com.dampcake.bencode.Type;
import com.google.gson.Gson;
import com.dampcake.bencode.Bencode;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

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


  private static void printPieces(byte[] pieces, int lenPieces){
    for(int i = 0; i < pieces.length/20; i++){
      int numIterations = i * 20;
      byte[] tmpBytes = new byte[20];
      int index = 0;
      for(int j = numIterations; j < numIterations + 20; j++){
        tmpBytes[index] = pieces[j];
        index++;
      }
      String hex = HexFormat.of().formatHex(tmpBytes);
      System.out.println(gson.toJson(hex));
    }
    return;
  }
  public static void printPeers(ByteBuffer peers){
    ArrayList<String> res = new ArrayList<>();
    Integer u = 0xFF;
    for(int i = 0; i < peers.limit(); i += 6){
      Integer p1 = peers.get(i) & u;
      Integer p2 = peers.get(i + 1) & u;
      Integer p3 = peers.get(i + 2) & u;
      Integer p4 = peers.get(i + 3) & u;

      ByteBuffer slice = ByteBuffer.wrap(new byte[]{peers.get(i + 4), peers.get(i + 5)});
      int r = slice.order(ByteOrder.BIG_ENDIAN).getShort() & 0xFFFF;
      String s = p1.toString() + '.' + p2.toString() + '.' + p3.toString() + '.' + p4.toString() + ":" + r;
      res.add(s);
    }
    for (var i : res){
      System.out.println(gson.toJson(i));
    }

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
        System.out.println("Piece Hashes: ");
        var pieces = info.get("pieces");
        Object rawLen = info.get("piece length");
        int lenPieces = 0;
        if(rawLen instanceof Long){
          lenPieces = ((Long) rawLen).intValue();
        }
        byte[] piecesInByte = ((ByteBuffer) pieces).array();
        System.out.println("Piece Length: " + lenPieces);
        System.out.println("Piece Hashes: ");
        printPieces(piecesInByte, lenPieces);



      }catch (RuntimeException e) {
        System.err.println(e.getMessage());
      }


    }else if("peers".equals(command)) {
      String fileName = args[1];
      try {
        byte[] bytes = Files.readAllBytes(Paths.get(fileName));
        Bencode bencode = new Bencode(true);
        Map<String, Object> f = bencode.decode(bytes, Type.DICTIONARY);
        Object announceObject = f.get("announce");

        byte[] announceBytes = ((ByteBuffer) announceObject).array();

        var trackerURL = new String(announceBytes, StandardCharsets.UTF_8);

        TrackerRequest r = new TrackerRequest();

        Map<String, Object> info = (Map<String, Object>) f.get("info");

        r.infoHash = strToSHA1(bencode.encode(info));
        r.left = info.get("length").toString();

        String infoHashWithPrecents = r.percentsEncoding();
        String encoded_info_hash = r.transformCharsIntoStrToHex(infoHashWithPrecents);
        String info_hash = "?info_hash=" + encoded_info_hash;
        String peer_id = "&peer_id=" + r.peerId;
        String port = "&port=" + r.port;
        String uploaded = "&uploaded=" + r.uploaded;
        String downloaded = "&downloaded=" + r.downloaded;
        String left = "&left=" + r.left;
        String compact = "&compact=" + r.compact;

        String url = trackerURL + info_hash + peer_id + port + uploaded + downloaded + left + compact;

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();

        HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        Bencode b = new Bencode(true);

        var check = b.decode(response.body(), Type.DICTIONARY);
        printPeers((ByteBuffer) check.get("peers"));

      }catch (RuntimeException e){
        System.err.println(e.getMessage());
      }

    }
      else {
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
