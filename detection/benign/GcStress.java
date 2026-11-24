import java.util.ArrayList;
import java.util.List;

/** GC-heavy allocator loop. Run: java GcStress.java [seconds] */
public class GcStress {
    public static void main(String[] args) {
        double seconds = args.length > 0 ? Double.parseDouble(args[0]) : 30;
        long end = System.nanoTime() + (long) (seconds * 1e9);
        long rounds = 0;
        while (System.nanoTime() < end) {
            List<byte[]> live = new ArrayList<>();
            for (int i = 0; i < 256; i++) {
                byte[] b = new byte[256 << 10];
                b[0] = (byte) i;
                live.add(b);
            }
            live.clear();
            if (rounds++ % 4 == 0) {
                System.gc();
            }
        }
        System.out.println("[benign-java] " + rounds + " rounds");
    }
}
