import java.util.*;

public class Solution {

    static int AnswerN;
    static int N = 10;
    static int K = 0;
    static int[] person = new int[100];
    static int[] road1 = new int[100];
    static int[] road2 = new int[100];

    static int count = 0;
    public static void main(String[] args) throws Exception {

        //System.setIn(new FileInputStream("C:\sample_input.txt"));
        Scanner sc = new Scanner(System.in);
        int T = sc.nextInt();

        for(int test_case = 1; test_case <= T; test_case++) {
            N = sc.nextInt();
            K = sc.nextInt();

            for(int i = 0; i< N-1; i++){
                road1[i] = sc.nextInt();
                road2[i] = sc.nextInt();
            }

            for(int i = 0; i< N; i++){
                person[i] = sc.nextInt();
                if(person[i] == 1){
                    count(i + 1);
                }
            }
            AnswerN = count;
            System.out.println("#"+test_case+" "+AnswerN);

        }
    }
    static void count(int num){
        for(int i = 0 ; i < N-1; i++){
            if(road1[i] == num){
                count++;
            }
            if(road2[i] == num){
                count++;
            }
            if(road1[i] == num  && road2[i] == num){
                count++;
            }
        }
    }

}