//Liron Avraham 201553864
//Adar Ovadya 	305264202

import java.io.*;
import java.net.URL;
import java.util.AbstractMap;
import java.util.ArrayList;

public class ex02_M2 {

    final private static int[] AesSbox = { 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76, 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0, 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15, 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75, 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84, 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf, 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8, 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2, 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73, 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb, 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79, 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08, 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a, 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e, 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf, 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };

    public static void main(String[] args) throws IOException {
        int number_of_power_traces = 10000;
        String user = "201553864";
        String serverURL = "http://aoi.ise.bgu.ac.il/encrypt?user=" + user;
        String filename = args[0];

        //System.out.println("Mean\tVariance"); // Print once at the start of your program and then
        //download_power_traces(filename, serverURL, number_of_power_traces);
        //getMeansVariances(filename);
        String key = extractKey(number_of_power_traces, filename, serverURL);
        System.out.print(user + "," + key);
    }

    public static String extractKey(int num_of_traces, String filename, String server_url) throws IOException {
        AbstractMap.SimpleEntry<int[][], double[][]> mestup = getMeasurements(filename, num_of_traces);
        int[][] plaintext_array = mestup.getKey();
        double[][] leaks_array = transpose( mestup.getValue());
        int[] key_array = new int[16];
        for (int k = 0; k < 16; k++) {
            double max = -1;
            for (int h = 0; h < 256; h++) {
                double[] h_vec = get_hipothesis_vector(plaintext_array, k, h);
                double[] cor = Correlation(h_vec, leaks_array);
                for (int c = 0; c < cor.length; c++) {
                    if(cor[c]>max){
                        max=cor[c];
                        key_array[k]=h;
                    }
                }
            }
        }
        String key = cor_to_str(key_array);

        return key;
    }

    private static AbstractMap.SimpleEntry<int[][], double[][]> getMeasurements(String filename, int num_of_traces) throws IOException {
        FileReader reader = new FileReader(filename);
        BufferedReader buffer = new BufferedReader(reader);
        String line;
        int count = 0;
        double[][] leaks_array = new double[num_of_traces][];
        int[][] plaintext_array = new int[num_of_traces][];
        int location = 0;
        while ((line = buffer.readLine()) != null && count++ < num_of_traces) {
            String plaintext = line.split("\\x5b")[0].split(":")[1].split("\"")[1];
            String[] leaks = line.split("\\[")[1].split("]")[0].split(",");
            double[] temp = new double[leaks.length];
            for (int i = 0; i < leaks.length; i++) {
                double leak = Double.parseDouble(leaks[i]);
                temp[i] = leak;
            }
            leaks_array[location] = temp;
            plaintext_array[location] = plaintext_to_int(plaintext);
            location++;
        }

        buffer.close();
        reader.close();
        return new AbstractMap.SimpleEntry<>(plaintext_array, leaks_array);
    }

    private static int[] plaintext_to_int(String spt) {
        int[] res = new int[16];
        for (int curr = 0,i=0; curr < spt.length(); curr+=2,i++) {
            String str_curr = spt.substring(curr, curr + 2);
            res[i] = Integer.parseInt(str_curr, 16);
        }
        return res;
    }

    private static double[][] transpose(double[][] matrix) {
        double[][] res = new double[matrix[0].length][matrix.length];
        for (int i = 0; i < matrix.length; i++) {
            for (int j = 0; j < matrix[0].length; j++) {
                res[j][i] = matrix[i][j];
            }
        }
        return res;
    }

    private static double[] Correlation ( double[] hyp,double[][] leaks){
        double[] res=new double[leaks.length];
        int i =0;
        for (double[] leak : leaks) {
            double cor = Correlation(hyp, leak);
            res[i++]=cor;
        }
        return res;
    }

    private static double Correlation(double hyp[], double[] leaks) {
        double mean_hypothesis = mean(hyp);
        double var_hypothesis = variance(hyp, mean_hypothesis);
        double mean_traces = mean(leaks);
        double var_traces = variance(leaks, mean_traces);
        double xy = 0;
        for (int j = 0; j < hyp.length; j++) {
            xy += hyp[j] * leaks[j];
        }
        xy = xy / hyp.length;
        return Math.abs((xy - mean_hypothesis * mean_traces) / Math.sqrt(var_hypothesis * var_traces));
    }

    private static double[] get_hipothesis_vector(int[][] plaintext_array, int k, int h) {
        double[] res = new double[plaintext_array.length];
        for (int d = 0; d < plaintext_array.length; d++) {
            res[d] = Integer.bitCount(AesSbox[ plaintext_array[d][k] ^ h]);
        }
        return res;
    }

    private static String cor_to_str(int[] most_cor) {
        StringBuilder sb = new StringBuilder();
        for (int c : most_cor) {
            String s = (String.format("%02x", c));
            sb.append(s);

        }

        return sb.toString();
    }

    public static void download_power_traces (String filename, String serverURL, int number_of_power_traces) throws Exception {
        URL url = new URL(serverURL);
        StringBuilder traces = new StringBuilder();
        for (int i = 0; i < number_of_power_traces; i++){
            String input = "";
            BufferedReader in = new BufferedReader (new InputStreamReader((url.openConnection()).getInputStream()));
            input = in.readLine();
            traces.append(input + '\n');
        }
        FileWriter file = new FileWriter(filename);
        file.write(traces.toString());
        file.flush();
        file.close();
    }

    //Retrieves samples from "filename" and use them for Average and Variance calculations
    private static void getMeansVariances(String filename) throws Exception {
        String input, plaintext;
        String[] leaks;
        FileReader fReader = new FileReader(filename);
        BufferedReader reader = new BufferedReader(fReader);
        ArrayList<ArrayList<Float>> float_leaks = new ArrayList<>();

        input = reader.readLine();
        plaintext = input.split("\\x5b")[0].split(":")[1].split("\"")[1];
        leaks= input.split("\\[")[1].split("]")[0].split(",");

        for (int i = 0; i < leaks.length; i++) {
            float_leaks.add(new ArrayList<Float>());
            float_leaks.get(i).add(Float.parseFloat(leaks[i]));
        }

        while ((input = reader.readLine()) != null){
            plaintext = input.split("\\x5b")[0].split(":")[1].split("\"")[1];
            leaks= input.split("\\[")[1].split("]")[0].split(",");

            for (int i = 0; i < leaks.length; i++) {
                float_leaks.get(i).add(Float.parseFloat(leaks[i]));
            }
        }

        reader.close();
        fReader.close();
        printAvgAndVariance(float_leaks);
    }

    //Prints all the Averages and Variances
    private static void printAvgAndVariance(ArrayList<ArrayList<Float>> traces) {
        for (ArrayList<Float> trace : traces){
            double[] current = getAverageAndVariance(trace);
            System.out.println(String.format("%.2f\t%.2f", current[0], current[1]));
        }
    }

    //Calculates the Average and the Variance of a given ArrayList of floats
    private static double[] getAverageAndVariance(ArrayList<Float> floats) {
        double sum = 0.0;
        double squares = 0.0;
        double[] ans = new double[2];
        for (float current : floats){
            sum += current;
            squares += (current*current);
        }
        ans[0] = sum/floats.size();
        ans[1] = squares/floats.size()-(sum/floats.size())*(sum/floats.size());
        return ans;
    }
}