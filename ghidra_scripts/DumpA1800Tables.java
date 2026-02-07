// Dump A1800 codec constant tables as Rust code
// @category Analysis
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

public class DumpA1800Tables extends ghidra.app.script.GhidraScript {

    private Memory mem;
    private AddressSpace space;

    @Override
    public void run() throws Exception {
        mem = currentProgram.getMemory();
        space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        // Bit allocation cost table: DAT_1000d9f0 (8 entries as i16)
        println("// Bit allocation cost per quantizer step index (0=finest, 7=unquantized)");
        dumpI16Array("BIT_ALLOC_COST", 0x1000d9f0, 8);

        // Bit allocation step table: DAT_100105a8 (32 entries as i16) 
        println("\n// Scale factor to bit count mapping");
        dumpI16Array("SCALE_FACTOR_BITS", 0x100105a8, 32);

        // Quantizer parameters tables (8 entries each)
        println("\n// Quantizer: number of levels minus 1 per step index");
        dumpI16Array("QUANT_LEVELS_M1", 0x100106b8, 8);
        println("\n// Quantizer: number of coded coefficients per step index");
        dumpI16Array("QUANT_NUM_COEFF", 0x100106c8, 8);
        println("\n// Quantizer: inverse step size (denominator-1) per step index");
        dumpI16Array("QUANT_INV_STEP", 0x100106d8, 8);
        println("\n// Quantizer: step size (Q15 reciprocal) per step index");
        dumpI16Array("QUANT_STEP_SIZE", 0x100106e8, 8);

        // Quantizer reconstruction levels: DAT_1000d8f0 (8 rows x 16 cols)
        println("\n// Quantizer reconstruction levels [step_index][position] (Q15)");
        dumpI16Array2D("QUANT_RECON_LEVELS", 0x1000d8f0, 8, 16);

        // Gain Huffman tree: DAT_1000d3e8
        // Need to figure out the size. Each entry is 4 bytes (2x i16).
        // The tree has nodes at indices 0x17=23 onward for the first tree.
        // Let me dump a big chunk and we'll trim later.
        println("\n// Huffman tree for subband gain coding");
        println("// Each entry: [left_child, right_child]");
        println("// Positive values = node index, negative values = negate to get decoded symbol");
        dumpI16Array("GAIN_HUFFMAN_TREE", 0x1000d3e8, 600);

        // Codebook tree pointers
        println("\n// Codebook Huffman tree pointers");
        long[] treeAddrs = new long[7];
        for (int i = 0; i < 7; i++) {
            Address addr = space.getAddress(0x1001058c + i * 4);
            treeAddrs[i] = mem.getInt(addr) & 0xFFFFFFFFL;
            println("// Tree " + i + " at 0x" + Long.toHexString(treeAddrs[i]));
        }

        // Dump each codebook tree (estimate 200 entries each)
        for (int i = 0; i < 7; i++) {
            long endAddr;
            if (i < 6) {
                endAddr = treeAddrs[i+1];
            } else {
                endAddr = treeAddrs[i] + 800; // estimate
            }
            int count = (int)((endAddr - treeAddrs[i]) / 2);
            if (count > 500) count = 500;
            println("\n// Codebook tree " + i);
            dumpI16Array("CODEBOOK_TREE_" + i, treeAddrs[i], count);
        }

        // Filterbank coefficient table pointers
        println("\n// Filterbank coefficient table pointers");
        long[] fbAddrs = new long[6];
        for (int i = 0; i < 6; i++) {
            Address addr = space.getAddress(0x1000ce70 + i * 4);
            fbAddrs[i] = mem.getInt(addr) & 0xFFFFFFFFL;
            println("// Filterbank table " + i + " at 0x" + Long.toHexString(fbAddrs[i]));
        }

        // Dump each filterbank coefficient table
        for (int i = 0; i < 5; i++) {
            int count = (int)((fbAddrs[i+1] - fbAddrs[i]) / 2);
            println("\n// Filterbank coefficients stage " + i);
            dumpI16Array("FILTERBANK_COEFF_" + i, fbAddrs[i], count);
        }
        // Last filterbank table - estimate size
        println("\n// Filterbank coefficients stage 5");
        dumpI16Array("FILTERBANK_COEFF_5", fbAddrs[5], 320);

        // Cosine modulation matrix: DAT_1000bed0
        println("\n// Cosine modulation matrix (320 entries)");
        dumpI16Array("COSINE_MOD_MATRIX", 0x1000bed0, 320);

        // Synthesis filter overlap state init: DAT_10010998 (320 entries)
        println("\n// Synthesis filter overlap offsets");
        dumpI16Array("SYNTH_OVERLAP_OFFSETS", 0x10010998, 320);

        // Subband excitation codebook mode table at PTR_DAT_1001058c
        // Referenced as (&PTR_DAT_1001058c)[iVar10]
        // This is already covered by the codebook tree pointers above.

        // Extra table: DAT_1000d8f0 positions table used in decode_subframes
        // Already dumped as QUANT_RECON_LEVELS

        println("\n// === Done dumping tables ===");
    }

    private void dumpI16Array(String name, long baseAddr, int count) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("pub const " + name + ": [i16; " + count + "] = [\n    ");
        for (int i = 0; i < count; i++) {
            Address addr = space.getAddress(baseAddr + i * 2);
            short val = mem.getShort(addr);
            sb.append(val);
            if (i < count - 1) sb.append(", ");
            if ((i + 1) % 16 == 0 && i < count - 1) sb.append("\n    ");
        }
        sb.append("\n];");
        println(sb.toString());
    }

    private void dumpI16Array2D(String name, long baseAddr, int rows, int cols) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("pub const " + name + ": [[i16; " + cols + "]; " + rows + "] = [\n");
        for (int r = 0; r < rows; r++) {
            sb.append("    [");
            for (int c = 0; c < cols; c++) {
                Address addr = space.getAddress(baseAddr + (r * cols + c) * 2);
                short val = mem.getShort(addr);
                sb.append(val);
                if (c < cols - 1) sb.append(", ");
            }
            sb.append("],\n");
        }
        sb.append("];");
        println(sb.toString());
    }
}
