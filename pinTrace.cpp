#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

std::ofstream traceFile;
ADDRINT mainExeStart;
ADDRINT mainExeEnd;
std::vector<char*> g_allocs;

KNOB< std::string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "trace.log", "输出文件名");

INT32 Usage()
{
	PIN_ERROR("生成主程序指令和上下文的追踪\n" + KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}

// 记录主程序的地址范围
VOID Image(IMG img, VOID* v)
{
	if (!IMG_IsMainExecutable(img)) {
		return;
	}
	mainExeStart = IMG_LowAddress(img);
	mainExeEnd = IMG_HighAddress(img);
	// traceFile << "[*] target exe loaded, address range: " << mainExeStart << " - " << mainExeEnd << std::endl;
}

VOID TraceLog(ADDRINT ip, char* bytesStr, char* disasmStr, CONTEXT* ctx) {
	std::string bytes(bytesStr);
	std::string disasm(disasmStr);
	std::ostringstream oss;
	oss << std::hex << std::setfill('0');

#ifdef _WIN64
	// 输出16个通用寄存器
	oss << "rax: " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_RAX) << " ";
	oss << "rbx: " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_RBX) << " ";
	oss << "rcx: " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_RCX) << " ";
	oss << "rdx: " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_RDX) << " ";
	oss << "rsi: " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_RSI) << " ";
	oss << "rdi: " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_RDI) << " ";
	oss << "rbp: " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_RBP) << " ";
	oss << "rsp: " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_RSP) << " ";
	oss << "r8: " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_R8) << " ";
	oss << "r9: " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_R9) << " ";
	oss << "r10: " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_R10) << " ";
	oss << "r11: " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_R11) << " ";
	oss << "r12: " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_R12) << " ";
	oss << "r13: " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_R13) << " ";
	oss << "r14: " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_R14) << " ";
	oss << "r15: " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_R15) << " ";

	// 输出eflags寄存器
	oss << "rflags: " << std::setw(8) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_RFLAGS);
#else

	// 输出8个通用寄存器
	oss << "eax: " << std::setw(8) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_EAX) << " ";
	oss << "ebx: " << std::setw(8) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_EBX) << " ";
	oss << "ecx: " << std::setw(8) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_ECX) << " ";
	oss << "edx: " << std::setw(8) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_EDX) << " ";
	oss << "esi: " << std::setw(8) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_ESI) << " ";
	oss << "edi: " << std::setw(8) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_EDI) << " ";
	oss << "ebp: " << std::setw(8) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_EBP) << " ";
	oss << "esp: " << std::setw(8) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_ESP) << " ";

	// 输出eflags寄存器
	oss << "eflags: " << std::setw(8) << PIN_GetContextReg(ctx, LEVEL_BASE::REG::REG_EFLAGS);
#endif

	traceFile << ip << " | "
		<< std::setw(44) << bytes << " | "
		<< std::setw(50) << disasm << " | "
		<< oss.str() << std::endl;
}

VOID Instruction(INS ins, VOID* v)
{
	ADDRINT addr = INS_Address(ins);
	if (addr < mainExeStart) return;
	if (addr > mainExeEnd) return;
	std::string disasm = INS_Disassemble(ins);
	UINT8 bytes[15] = { 0 };
	USIZE length = INS_Size(ins);
	size_t copied = PIN_SafeCopy(bytes, reinterpret_cast<const void*>(addr), length);

	std::ostringstream oss; // 指令字节码
	oss << std::hex << std::setfill('0');
	for (size_t i = 0; i < copied; i++) {
		oss << std::setw(2) << static_cast<unsigned int>(bytes[i]);
		if (i < 14) {
			oss << " ";
		}
	}

	// 堆上创建字符串的副本 传递给插桩函数
	char* bytesStr = strdup(oss.str().c_str());
	char* disasmStr = strdup(disasm.c_str());
	// 记录地址 程序推出前释放
	g_allocs.push_back(bytesStr);
	g_allocs.push_back(disasmStr);

	INS_InsertCall(ins, IPOINT_BEFORE, MAKE_AFUNPTR(TraceLog),
		IARG_INST_PTR,
		IARG_PTR, bytesStr,
		IARG_PTR, disasmStr,
		IARG_CONTEXT,
		IARG_END
	);
}

VOID Fini(INT32 code, VOID* v)
{
	for (char* p : g_allocs) free(p);
	g_allocs.clear();
	if (traceFile.is_open()) { traceFile.close(); }
}

// 指令地址 指令字节码 指令汇编语句 寄存器上下文
int main(int argc, char* argv[])
{
	PIN_InitSymbols();
	if (PIN_Init(argc, argv)) return Usage();

	traceFile.open(KnobOutputFile.Value().c_str());
	traceFile << std::left << std::hex << std::setfill(' ');
	traceFile.setf(std::ios::showbase);

	IMG_AddInstrumentFunction(Image, 0);
	INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddFiniFunction(Fini, 0);
	PIN_StartProgram();
	return 0;
}
