import java.util.*;

public class Main {

    /*
    2
8 1
1 4 2
5 4 2
7 5 1
5 8 2
3 7 0
6 5 1
2 6 0
1 0 0 1 1 0 0 1

     */
    static int AnswerN;
    static int N = 10;
    static int K = 0;
    static int[] person = new int[8];
    static int[] road1 = new int[7];
    static int[] road2 = new int[7];

    static int count = 0;
    public static void main(String[] args) throws Exception {

        //System.setIn(new FileInputStream("C:\sample_input.txt"));
        Scanner sc = new Scanner(System.in);
        K = 1;
        int T = 2;

        for(int test_case = 1; test_case <= T; test_case++) {
            N = 12;
            K = 1;

            for(int i = 0; i< N-1; i++){
                road1[i] = i;
                road2[i] = i+1;
            }

            for(int i = 0; i< N; i++){
                person[i] = 1;
                if(person[i] == 1){
                    count++;
                }
            }
            AnswerN = count;
            System.out.println("#"+test_case+" "+AnswerN);
        }
    }


}