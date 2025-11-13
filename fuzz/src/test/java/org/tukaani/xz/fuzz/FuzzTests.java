package org.tukaani.xz.fuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.apache.commons.compress.compressors.CompressorInputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorInputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorOutputStream;
import org.tukaani.xz.ARM64Options;
import org.tukaani.xz.ARMOptions;
import org.tukaani.xz.ARMThumbOptions;
import org.tukaani.xz.ArrayCache;
import org.tukaani.xz.BasicArrayCache;
import org.tukaani.xz.DeltaOptions;
import org.tukaani.xz.FilterOptions;
import org.tukaani.xz.FinishableOutputStream;
import org.tukaani.xz.IA64Options;
import org.tukaani.xz.LZMA2Options;
import org.tukaani.xz.PowerPCOptions;
import org.tukaani.xz.RISCVOptions;
import org.tukaani.xz.SPARCOptions;
import org.tukaani.xz.SeekableInputStream;
import org.tukaani.xz.SeekableXZInputStream;
import org.tukaani.xz.UnsupportedOptionsException;
import org.tukaani.xz.X86Options;
import org.tukaani.xz.XZ;
import org.tukaani.xz.XZIOException;
import org.tukaani.xz.XZInputStream;
import org.tukaani.xz.XZOutputStream;
import org.apache.commons.compress.compressors.CompressorOutputStream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

class FuzzTests {
    /**
     * Verifies that data compressed by XZ returns to its original state after decompression.
     */
    @FuzzTest
    public void fuzzRoundTrip(FuzzedDataProvider fdp) {
        // Use fuzzer data to set various options
        int preset = fdp.consumeInt(0, LZMA2Options.PRESET_MAX);
        int checkType = fdp.pickValue(new int[]{XZ.CHECK_NONE, XZ.CHECK_CRC32, XZ.CHECK_CRC64, XZ.CHECK_SHA256});
        boolean useDelta = fdp.consumeBoolean();
        boolean useBCJ = fdp.consumeBoolean();
        int deltaDist = useDelta ? fdp.consumeInt(DeltaOptions.DISTANCE_MIN, DeltaOptions.DISTANCE_MAX) : 1;
        byte[] inputData = fdp.consumeRemainingAsBytes();

        FilterOptions[] filters = new FilterOptions[useDelta && useBCJ ? 3 : useDelta || useBCJ ? 2 : 1];
        try {
            int idx = 0;
            if (useDelta) {
                filters[idx++] = new DeltaOptions(deltaDist);
            }
            if(useBCJ) {
                filters[idx++] = getRandomBCJ(fdp);
            }
            LZMA2Options lzma2 = new LZMA2Options(preset);
            filters[idx] = lzma2;
        } catch (UnsupportedOptionsException e) {
            throw new RuntimeException(e);
        }

        byte[] compressed = new byte[0];
        try {
            // Encode
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (XZOutputStream xzos = new XZOutputStream(baos, filters, checkType)) {
                xzos.write(inputData);
            }
            compressed = baos.toByteArray();
        } catch (IOException ignored) {}

        try{
            // Decode
            ByteArrayInputStream bais = new ByteArrayInputStream(compressed);
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            try (XZInputStream xzis = new XZInputStream(bais)) {
                byte[] buffer = new byte[8192];
                int n;
                while ((n = xzis.read(buffer)) != -1) {
                    result.write(buffer, 0, n);
                }
            }

            // Verify round trip
            byte[] decompressed = result.toByteArray();
            if (!Arrays.equals(inputData, decompressed)) {
                throw new AssertionError("Roundtrip failed: data corrupted");
            }

        } catch (IOException e) {
            throw new RuntimeException("Decoder failed on valid input");
        }
    }

    /**
     * Fuzzes the XZ filter encoders by selecting one of the architecture-specific
     * FilterOptions (x86, PowerPC, IA64, ARM, etc.) and feeding it arbitrary input.
     */
    @FuzzTest
    public void fuzzEncoders(FuzzedDataProvider data) {
        final FilterOptions[] ENCODERS = {
                new X86Options(),
                new PowerPCOptions(),
                new IA64Options(),
                new ARMOptions(),
                new ARMThumbOptions(),
                new SPARCOptions(),
                new ARM64Options(),
                new RISCVOptions()
        };

        if (data.remainingBytes() == 0) return;

        FilterOptions encoder = data.pickValue(ENCODERS);
        byte[] input = data.consumeRemainingAsBytes();

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            FinishableOutputStream base = new FinishableWrapperOutputStream(baos);
            FinishableOutputStream stream = encoder.getOutputStream(base, ArrayCache.getDefaultCache());
            stream.write(input);
            stream.finish();
        } catch (IOException ignored) {
        }
    }

    /**
     * Fuzzes the XZ decoder by feeding arbitrary byte sequences into an {@link XZInputStream}
     * and attempting to decompress them. Note that seed inputs are used to guide the fuzzer.
     */
    @FuzzTest
    public void fuzzDecode(FuzzedDataProvider fdp) {
        byte[] inputData = fdp.consumeRemainingAsBytes();

        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(inputData);
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            try (XZInputStream xzIn = new XZInputStream(bais)) {
                byte[] buffer = new byte[8192];
                int n;
                while ((n = xzIn.read(buffer)) != -1) {
                    result.write(buffer, 0, n);
                }
            }
        } catch (IOException ignored) {
        }
    }

    /**
     * Fuzzes the XZ decompressor to detect inputs that expand to extremely large
     * outputs relative to their size.
     */
    @FuzzTest
    public void fuzzDecompressionBomb(FuzzedDataProvider fdp) {
        final int MAX_EXPANSION_RATIO = 80;
        byte[] inputData = fdp.consumeRemainingAsBytes();
        long maxAllowedSize = (long) inputData.length * MAX_EXPANSION_RATIO + (1024 * 1024);

        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(inputData);
            try (XZInputStream xzIn = new XZInputStream(bais)) {
                byte[] uncompressedData = xzIn.readAllBytes();

                int uncompressedSize = uncompressedData.length;
                if (uncompressedSize > maxAllowedSize) {
                    throw new RuntimeException("Possible Zip Bomb detected! Input size: " +
                        inputData.length + ", Produced: " + uncompressedSize + " bytes");
                }
            }
        } catch (IOException ignored) {
        }
    }

    /**
     * Fuzzes support for concatenated XZ streams by generating multiple independent
     * XZ-compressed segments and joining them into a single byte sequence before
     * decoding.
     */
    @FuzzTest
    public void fuzzConcatenatedStreams(FuzzedDataProvider fdp) throws Exception {
        int streams = fdp.consumeInt(1, 5);
        ByteArrayOutputStream combined = new ByteArrayOutputStream();

        // Create N concatenated XZ streams
        for (int i = 0; i < streams; i++) {
            byte[] data = fdp.consumeBytes(256);
            try (XZOutputStream xzOut = new XZOutputStream(combined, new LZMA2Options())) {
                xzOut.write(data);
            }
        }

        byte[] multiXZ = combined.toByteArray();

        // Decode concatenated streams
        try (XZInputStream in = new XZInputStream(new ByteArrayInputStream(multiXZ))) {
            while (in.read() != -1) {}
        } catch (IOException ignored) {}
    }

    /**
     * Fuzzes the seekable XZ decoding implementation by compressing fuzzer input data
     * and then exercising random seek and read operations on a {@link SeekableXZInputStream}.
     */
    @FuzzTest
    public void fuzzSeekableInputStreams(FuzzedDataProvider fdp) {
        byte[] inputData = fdp.consumeBytes(2048);
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            XZOutputStream xzos = new XZOutputStream(baos, new LZMA2Options());
            xzos.write(inputData);
            xzos.close();

            byte[] compressed = baos.toByteArray();
            SeekableInMemoryByteSource source = new SeekableInMemoryByteSource(compressed);
            SeekableXZInputStream seekStream = new SeekableXZInputStream(source);
            int operations = fdp.consumeInt(1, 20);
            for (int i = 0; i < operations; i++) {
                if (fdp.consumeBoolean()) {
                    long pos = fdp.consumeLong(0, inputData.length);
                    seekStream.seek(pos);
                } else {
                    seekStream.read();
                }
            }
            seekStream.close();
        } catch (IOException ignored) {
        }
    }

    /**
     * Fuzzes interactions between LZMA2 dictionary sizes, preset levels, and the
     * decoder’s memory-limit enforcement. This test helps detect cases where the
     * XZ decoder may allocate excessively large dictionaries or fail to respect
     * configured memory limits.
     * Note that this fuzz test triggers an {@link OutOfMemoryError}.
     */
    @FuzzTest
    public void fuzzDictionarySizes(FuzzedDataProvider fdp) {
        byte[] inputData = fdp.consumeBytes(100);
        boolean useMaxDictSize = fdp.consumeBoolean();
        int preset =  fdp.consumeInt(0, 9);

        try {
            // Compress
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            LZMA2Options options = new LZMA2Options(preset);

            if (useMaxDictSize) {
                options.setDictSize(LZMA2Options.DICT_SIZE_MAX);
            }

            XZOutputStream out = new XZOutputStream(baos, options);
            out.write(inputData);
            out.close();

            byte[] compressed = baos.toByteArray();

            // Decompress with strict memory limit
            int memoryLimitKiB = 10 * 1024;

            try (XZInputStream in = new XZInputStream(
                    new ByteArrayInputStream(compressed), memoryLimitKiB)) {
                in.readAllBytes();
            }
        } catch (IOException | IllegalArgumentException ignored) {
        } catch (OutOfMemoryError e) {
            throw new RuntimeException("OutOfMemoryError: " +
                    e.getMessage());
        }
    }

    /**
     * Fuzzes cross-compatibility between the xz-java implementation and Apache
     * Commons Compress by compressing and decompressing fuzz-generated data using
     * both libraries and verifying that they produce identical results.
     */
    @FuzzTest
    public void fuzzXzVsApacheCommons(FuzzedDataProvider fdp) {
        byte[] inputData = fdp.consumeRemainingAsBytes();

        // Compression with XZ
        byte[] xzCompressed = new byte[0];
        try {
            // Encode
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (XZOutputStream xzos = new XZOutputStream(baos, new LZMA2Options())) {
                xzos.write(inputData);
            }
            xzCompressed = baos.toByteArray();
        } catch (IOException ignored) {}

        // Compression with Apache Compress
        byte[] apacheCompressed = new byte[0];
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (CompressorOutputStream<XZOutputStream> out = new XZCompressorOutputStream(baos)) {
                out.write(inputData);
            }
            apacheCompressed = baos.toByteArray();
        } catch (IOException ignored) {}

        // Cross-decompress: Apache decompresses XZ
        byte[] crossApache = new byte[0];
        try {
            CompressorInputStream in = new XZCompressorInputStream(new ByteArrayInputStream(xzCompressed));
            crossApache = in.readAllBytes();
        } catch (IOException ignored) {}

        // Cross-decompress: XZ decompressed Apache
        byte[] crossXZ = new byte[0];
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(apacheCompressed);
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            try (XZInputStream xzis = new XZInputStream(bais)) {
                byte[] buffer = new byte[8192];
                int n;
                while ((n = xzis.read(buffer)) != -1) {
                    result.write(buffer, 0, n);
                }
            }
            crossXZ = result.toByteArray();
        } catch (IOException ignored) {}

        // Compare decompressed results
        if (!Arrays.equals(crossXZ, crossApache)) {
            throw new AssertionError("Cross-decompression mismatch");
        }
    }

    /**
     * Fuzzes the {@link BasicArrayCache} by repeatedly compressing and decompressing
     * fuzz-generated data using a single shared cache instance. The goal is to verify
     * that the cache behaves correctly under varied workloads and does not introduce data
     * corruption or state inconsistencies across multiple encoder and decoder cycles.
     */
    @FuzzTest
    public void fuzzBasicArrayCache(FuzzedDataProvider fdp) {
        BasicArrayCache cache = new BasicArrayCache();

        int iterations = fdp.consumeInt(2, 5);

        for (int i = 0; i < iterations; i++) {
            // Generate random input for this iteration
            byte[] inputData = fdp.consumeBytes(fdp.consumeInt(1, 4096));
            if (inputData.length == 0) return;

            // Compress using the shared cache
            byte[] compressed;
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                LZMA2Options options = new LZMA2Options();
                options.setPreset(fdp.consumeInt(0, 5));

                // Pass the cache explicitly to XZOutputStream
                try (XZOutputStream xzos = new XZOutputStream(baos, new FilterOptions[]{options}, XZ.CHECK_CRC64, cache)) {
                    xzos.write(inputData);
                }
                compressed = baos.toByteArray();
            } catch (IOException e) {
                return;
            }

            // Decompress using the shared cache
            ByteArrayOutputStream decompressedOut = new ByteArrayOutputStream();
            // Pass the cache explicitly to XZInputStream
            try (XZInputStream xzis = new XZInputStream(new ByteArrayInputStream(compressed), cache)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = xzis.read(buffer)) != -1) {
                    decompressedOut.write(buffer, 0, len);
                }
            } catch (IOException ignored) { }

            // Verify integrity
            if (!Arrays.equals(inputData, decompressedOut.toByteArray())) {
                throw new AssertionError("Data corruption detected when using BasicArrayCache");
            }
        }
    }

    /**
     * Fuzzes the standalone LZMA2 encoder by generating a wide range of option
     * combinations and attempting to compress arbitrary data using those parameters.
     */
    @FuzzTest
    public void fuzzLZMA2Encoder(FuzzedDataProvider fdp) {
        if (fdp.remainingBytes() == 0) return;
        try {
            LZMA2Options options = new LZMA2Options();
            options.setPreset(fdp.consumeInt(0, LZMA2Options.PRESET_MAX));
            options.setDictSize(fdp.consumeInt(LZMA2Options.DICT_SIZE_MIN, LZMA2Options.DICT_SIZE_MAX));
            options.setNiceLen(fdp.consumeInt(LZMA2Options.NICE_LEN_MIN, LZMA2Options.NICE_LEN_MAX));
            options.setMatchFinder(fdp.consumeInt(0, 5));
            options.setDepthLimit(fdp.consumeInt(0, 100));
            options.setLc(fdp.consumeInt(0, 8));
            options.setLp(fdp.consumeInt(0, 4));
            options.setPb(fdp.consumeInt(0, 4));

            // compress
            byte[] inputData = fdp.consumeRemainingAsBytes();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            FinishableOutputStream base = new FinishableWrapperOutputStream(baos);

            try (FinishableOutputStream lzma2Out = options.getOutputStream(base, ArrayCache.getDefaultCache())) {
                lzma2Out.write(inputData);
                lzma2Out.finish();
            }
            byte[] compressed = baos.toByteArray();

            // decompress
            if (compressed.length > 0) {
                try (XZInputStream xzis = new XZInputStream(new ByteArrayInputStream(compressed))) {
                    while (xzis.read() != -1) {}
                } catch (XZIOException ignored) {
                }
            }

        } catch (IOException ignored) {
        }
    }

    static class FinishableWrapperOutputStream extends FinishableOutputStream {
        private final ByteArrayOutputStream out;

        FinishableWrapperOutputStream(ByteArrayOutputStream out) {
            this.out = out;
        }

        public void write(int b) throws java.io.IOException {
            out.write(b);
        }

        public void flush() throws java.io.IOException {
            out.flush();
        }

        public void finish() throws java.io.IOException {
        }
    }

    private static class SeekableInMemoryByteSource extends SeekableInputStream {
        private final byte[] buf;
        private int pos;

        public SeekableInMemoryByteSource(byte[] buf) {
            this.buf = buf;
            this.pos = 0;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (pos >= buf.length) return -1;
            int avail = buf.length - pos;
            if (len > avail) len = avail;
            System.arraycopy(buf, pos, b, off, len);
            pos += len;
            return len;
        }

        @Override
        public void seek(long pos) throws IOException {
            this.pos = (int) pos;
        }

        @Override
        public long length() throws IOException {
            return buf.length;
        }

        @Override
        public long position() throws IOException {
            return pos;
        }

        @Override
        public void close() throws IOException {}

        @Override
        public int read() throws IOException {
            if (pos >= buf.length) return -1;
            return buf[pos++] & 0xFF;
        }
    }

    private FilterOptions getRandomBCJ(FuzzedDataProvider fdp) {
        switch (fdp.consumeInt(0, 7)) {
            case 0: return new X86Options();
            case 1: return new ARMOptions();
            case 2: return new ARM64Options();
            case 3: return new ARMThumbOptions();
            case 4: return new PowerPCOptions();
            case 5: return new IA64Options();
            case 6: return new RISCVOptions();
            default: return new SPARCOptions();
        }
    }
}