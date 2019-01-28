package PasswordHasherTest;

import io.standardcore.security.BufferUtil;
import io.standardcore.security.random.DefaultSecureRandomGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Collectors;

public class RandomGeneratorTests {
    @Test
    public void TestSecureRandomGenerator() throws InterruptedException {
        int size = 10000;
        List<byte[]> results = new Vector<>();
        CountDownLatch wg = new CountDownLatch(size);
        for (int i = 0; i < size; i++)
        {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    results.add(new DefaultSecureRandomGenerator().generateBytes(32));
                    wg.countDown();
                }
            }).start();
        }
        wg.await();
        Assertions.assertFalse(results.isEmpty());
        Map<EqualableBinary, List<EqualableBinary>> maps = results.stream().map(x -> new EqualableBinary(x))
                .collect(Collectors.groupingBy(x -> x));
        boolean flag = maps.entrySet().stream().anyMatch(x -> x.getValue().size() > 1);
        Assertions.assertFalse(flag);
    }

    private static class EqualableBinary{
        private final byte[] source;

        public EqualableBinary(byte[] source) {
            this.source = source;
        }

        public byte[] getSource() {
            return source;
        }

        @Override
        public boolean equals(Object obj) {
           if(obj instanceof EqualableBinary) return BufferUtil.byteArraysEqual(source, ((EqualableBinary)obj).getSource());
           return false;
        }

    }
}
