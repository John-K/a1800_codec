// Dump small A1800 tables
// @category Analysis
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

public class DumpSmallTables extends ghidra.app.script.GhidraScript {
    private Memory mem;
    private AddressSpace space;

    @Override
    public void run() throws Exception {
        mem = currentProgram.getMemory();
        space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        
        dumpI16("BIT_ALLOC_COST", 0x1000d9f0L, 8);
        dumpI16("QUANT_LEVELS_M1", 0x100106b8L, 8);
        dumpI16("QUANT_NUM_COEFF", 0x100106c8L, 8);
        dumpI16("QUANT_INV_STEP", 0x100106d8L, 8);
        dumpI16("QUANT_STEP_SIZE", 0x100106e8L, 8);
        
        // Filterbank pointers
        for (int i = 0; i < 6; i++) {
            Address addr = space.getAddress(0x1000ce70L + i * 4);
            long ptr = mem.getInt(addr) & 0xFFFFFFFFL;
            println("FB_PTR_" + i + "=0x" + Long.toHexString(ptr));
        }
        
        // Codebook tree pointers
        for (int i = 0; i < 7; i++) {
            Address addr = space.getAddress(0x1001058cL + i * 4);
            long ptr = mem.getInt(addr) & 0xFFFFFFFFL;
            println("CB_PTR_" + i + "=0x" + Long.toHexString(ptr));
        }
    }

    private void dumpI16(String name, long baseAddr, int count) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append(name + "=[");
        for (int i = 0; i < count; i++) {
            Address addr = space.getAddress(baseAddr + i * 2);
            short val = mem.getShort(addr);
            if (i > 0) sb.append(",");
            sb.append(val);
        }
        sb.append("]");
        println(sb.toString());
    }
}
