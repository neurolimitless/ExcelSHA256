import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

public class DataProcessor {

    public static String generateString(String... elements) {
        StringBuilder builder = new StringBuilder();
        for (String element : elements) {
            if (element.length() == 1) builder.append("0").append(element);
            else builder.append(element);
        }
        return builder.toString();
    }

    public static String getHexLength(String input) {
        String result = input.replace(" ", "");
        return Integer.toHexString(result.length() / 2);
    }

    /**
     * @param input    - text that must be formatted.
     * @param append0x - 'true' - appending 0x before formatted text (output usage)
     * @return formatted string with whitespaces between each two symbols and with '0x'
     * at the beginning of the string if 'append0x' is true.
     */
    public static String format(String input, boolean append0x) {
        String result = input.replace(" ", ""); //remove all whitespaces
        StringBuilder builder = new StringBuilder(); //adding whitespace after each 2 symbols
        if (input.length() == 1) builder.append("0");
        for (int i = 0; i < result.length(); i++) {
            if (i > 0 && i % 2 == 0) builder.append(" ");
            builder.append(result.charAt(i));
        }
        if (append0x) return "0x " + builder.toString().toUpperCase();
        else return builder.toString().toUpperCase();
    }


    //replaces first <?> to value.
    private static void replaceWildcard(String[] data, String value) {
        for (int i = 0; i < data.length; i++) {
            if (data[i].equals("?")) {
                data[i] = value;
                break;
            }
        }
    }

    private static String[] readConfig(String configPath) throws IOException {
        List<String> configData = new ArrayList<>();
        File file = new File(configPath);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        while ((line = reader.readLine()) != null) {
            configData.add(line);
        }
        System.out.println("Config size: " + configData.size());
        String[] result = new String[configData.size()];
        for (int i = 0; i < configData.size(); i++) {
            result[i] = configData.get(i);
        }
        return result;
    }

    private static String formatByLength(String text, int length) {
        int byteLength = text.length() / 2;
        StringBuilder builder = new StringBuilder();
        if (length > byteLength) {
            for (int i = 0; i < length - byteLength; i++) {
                if (byteLength == 0 && i + 1 == length - byteLength)
                    builder.append("0"); //for cases where hexadecimal representation of decimal number has 1 symbol
                else builder.append("00 ");
            }
        }
        builder.append(format(text, false));
        return builder.toString();
    }

    private static String valueInBrackets(String s) {
        return s.substring(s.indexOf("(") + 1, s.indexOf(")"));
    }

    private static String valueAfterBrackets(String s) {
        return s.substring(s.indexOf(")") + 2); //we don't include ')' and whitespace after, so index+2;
    }


    public static String[] DGI0702(String[] data) {
        StringTokenizer tokenizer = new StringTokenizer(data[8], ";");
        String[] parsedData = new String[6];
        for (int i = 0; i < 6; i++) {
            parsedData[i] = tokenizer.nextToken();
        }
        byte RSAKEYlength = Byte.parseByte(data[1]);
        byte AESKEYlength = Byte.parseByte(data[4]);
        byte OKIMAClength = Byte.parseByte(data[10]);
        String RSAKEY = data[2];
        String AESKEY = data[5];
        String OKIMAC = data[11];
//        String hashRSAKEY = Cipher.processSalt(RSAKEY, RSAKEYlength);
        String hashAESKEY = CipherProcessor.processSalt(AESKEY, AESKEYlength);
        String hashOKIMAC = CipherProcessor.processSalt(OKIMAC, OKIMAClength);
//        System.out.println(hashRSAKEY);
        String formatId = valueAfterBrackets(parsedData[0]);
        String abaNumber = valueAfterBrackets(parsedData[1]);
        String bankAccountNumber = valueAfterBrackets(parsedData[2]);
        String bankAccountType = valueAfterBrackets(parsedData[3]);
        String issuingDevice = valueAfterBrackets(parsedData[4]);
        String rfu = valueAfterBrackets(parsedData[5]);
        /**
         * %s FORMAT_ID (1) 1;
         * ABA_NUMBER (6) 123456789012;
         * BANK_ACCOUNT_NUMBER (9) 123456789012345678;
         * BANK_ACCOUNT_TYPE (1) 4;
         * ISSUING_DEVICE (3) abc;
         * RFU (12) abcdefghijkl;
         */
//        System.out.println(formatId);
//        System.out.println(abaNumber);
//        System.out.println(bankAccountNumber);
//        System.out.println(bankAccountType);
//        System.out.println(issuingDevice);
//        System.out.println(rfu);
        // 01 12 34 56 78 90 12 12 34 56 78 90 12 34 56 78 04 61 62 63 61 62 63 64 65 66 67 68 69 6A 6B 6C
        byte formatIdLength = Byte.parseByte(valueInBrackets(parsedData[0]));
        byte abaNumberLength = Byte.parseByte(valueInBrackets(parsedData[1]));
        byte bankAccountNumberLength = Byte.parseByte(valueInBrackets(parsedData[2]));
        byte bankAccountTypeLength = Byte.parseByte(valueInBrackets(parsedData[3]));
        byte issuingDeviceLength = Byte.parseByte(valueInBrackets(parsedData[4]));
        byte rfuLength = Byte.parseByte(valueInBrackets(parsedData[5]));
        String hashedIssuingDevice = CipherProcessor.asciiToHex(issuingDevice);
        String hashedRFU = CipherProcessor.asciiToHex(rfu);
        String processedValue = generateString(formatId, abaNumber, bankAccountNumber, bankAccountType, hashedIssuingDevice, hashedRFU);
        System.out.println(RSAKEY);
        System.out.println(hashAESKEY); // IV - initial vector
        System.out.println(processedValue);
        System.out.println(hashOKIMAC);
        String key = "16symbolpassword";
        String payload = CipherProcessor.AES256(key, processedValue, hashAESKEY);
        String hmacPayload = CipherProcessor.hmacSHA256(payload, hashOKIMAC, 1);
        String configPath = "dgi0702.cfg";
        String outputValue = generateString("13", format(String.valueOf(RSAKEYlength), false), RSAKEY, //format(String.valueOf(RSAKEYlength) because its could be 1 instead of 01
                "14", String.valueOf(hashAESKEY.length() / 2), hashAESKEY,
                "15", String.valueOf(payload.length()), payload,
                "16", "32", hmacPayload);
        System.out.println(payload);
        try {
            String[] result = readConfig(configPath);
            replaceWildcard(result, format(String.valueOf(RSAKEYlength), true));
            replaceWildcard(result, format(RSAKEY, true));
            replaceWildcard(result, format(String.valueOf(hashAESKEY.length() / 2), true));
            replaceWildcard(result, format(hashAESKEY, true));
            replaceWildcard(result, "0x " + payload.length() / 2); //we don't use format because it will output 0x 16 0 instead of 0x 160
            replaceWildcard(result, format(payload, true));
            replaceWildcard(result, format(hmacPayload, true));
            replaceWildcard(result, getHexLength(outputValue));
            replaceWildcard(result, format(outputValue, false));
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String[] DGI0701(String[] data) {
        //processing HMAC info
        StringTokenizer tokenizer = new StringTokenizer(data[2], ";"); //third array cell contains string
        String[] parsedData = new String[3];
        for (int i = 0; i < 3; i++) {
            parsedData[i] = tokenizer.nextToken();
        }
        String plainSalt = valueAfterBrackets(parsedData[2]);
        String plainIterations = valueAfterBrackets(parsedData[1]);
        String plainKey = valueAfterBrackets(parsedData[0]);
        String saltBytes = valueInBrackets(parsedData[2]);
        String iterationBytes = valueInBrackets(parsedData[1]);
        String keyBytes = valueInBrackets(parsedData[0]);
        String hashedSalt = CipherProcessor.processSalt(plainSalt, 16);
        String hashedIterations = Integer.toHexString(Integer.parseInt(plainIterations));
        String hashedKey = Integer.toHexString(Integer.parseInt(plainKey));
        String processedValue = formatByLength(hashedKey, Integer.parseInt(keyBytes)) +
                formatByLength(hashedIterations, Integer.parseInt(iterationBytes)) +
                hashedSalt;
//        System.out.println(format(processedValue)); //processed HMAC
        //processing ID-Type
        int idLength = Integer.parseInt(data[4], 16);
        String processedId = data[5];
        if (processedId.length() != idLength * 2) processedId = formatByLength(processedId, idLength);
//        System.out.println(processedId); //processed ID
        //processing Cardholder
        String hashedCardholder = CipherProcessor.asciiToHex(data[8]); //cardholder number stored in eight cell
//        System.out.println(format(hashedCardholder)); //processed Cardholder
        //saving to file
        try {
            String configPath = "dgi0701.cfg";
            String[] result = readConfig(configPath);
            String length = "0x " + getHexLength(processedValue);
            replaceWildcard(result, length);
            replaceWildcard(result, format(processedValue, true));
            replaceWildcard(result, "0x 0" + idLength);//TODO fix this
            replaceWildcard(result, "0x " + processedId);
            //TODO !!! WARNING, WRONG OUTPUT!!!
            String output = CipherProcessor.hmacSHA256(hashedCardholder, processedValue, 10000);
            System.out.println(output);
            String saltLength = "22"; //this magic numbers will be removed after we solve problem with hashing
            String outputLength = "32";
            replaceWildcard(result, "0x " + outputLength);
            replaceWildcard(result, format(output, true));
            String outputValue = "10" + saltLength + processedValue + "110" + idLength + processedId + "12" + outputLength + output;
            replaceWildcard(result, getHexLength(outputValue));
            replaceWildcard(result, format(outputValue, true));
            return result;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }


}