import java.lang.ref.WeakReference;

public class GCTest {
    public static void main(String[] args) {
        int loops = 0;
        while (true) {
            System.out.println("Iteration: " + ++loops);
            if (true) {
                for (int i = 0; i <15000; i++) {
                    Object obj = new Object();
                    WeakReference ref = new WeakReference<Object>(obj);
                    obj = null;
                    if (false) {
                        while(ref.get() != null) {
                            System.out.printf("!");
                            System.gc();
                        }
                    }
                }
                //System.gc();
            } else {
              //System.gc();
            }
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}