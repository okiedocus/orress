public class Check {
    static final String SECRET = "flag{jvm_r3v3rs3}";
    int total;

    public boolean check(String pw) {
        int t = 0;
        for (int i = 0; i < pw.length(); i++) {
            t += pw.charAt(i) ^ (i + 7);
        }
        return t == 1337;
    }

    public static void main(String[] args) {
        System.out.println("enter password:");
    }
}
