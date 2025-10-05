#include "virtualization_engine.h"
#include "assembler.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>  // For randomization

// Virtual machine opcodes
typedef enum {
    VM_NOP = 0x00,
    VM_MOV_REG_IMM = 0x01,
    VM_ADD_REG_IMM = 0x02,
    VM_SUB_REG_IMM = 0x03,
    VM_PUSH_REG = 0x04,
    VM_POP_REG = 0x05,
    VM_CALL = 0x06,
    VM_RET = 0x07,
    VM_JMP = 0x08,
    VM_CMP_REG_IMM = 0x09,
    VM_JE = 0x0A,
    VM_JNE = 0x0B,
    VM_MOV_REG_REG = 0x0C,
    VM_ADD_REG_REG = 0x0D,
    VM_SUB_REG_REG = 0x0E,
    VM_END = 0xFF
} vm_opcode_t;

// Virtual machine instruction structure
typedef struct {
    vm_opcode_t opcode;
    uint8_t operand1;  // Register or immediate value
    uint32_t operand2; // Immediate value or address
} vm_instruction_t;

// Simple virtual machine state
typedef struct {
    uint64_t registers[16];  // Simplified register file (RAX, RBX, etc.)
    uint64_t stack[1024];    // VM stack
    uint32_t stack_ptr;
    uint32_t ip;            // Instruction pointer
    uint8_t* bytecode;      // Bytecode to execute
    uint32_t bytecode_size; // Size of bytecode
} vm_state_t;

// Translate Capstone instruction to VM bytecode
vm_bytecode* translate_to_vm_bytecode(const instruction_list* instructions) {
    // Allocate space for VM bytecode (conservatively estimated)
    vm_bytecode* result = (vm_bytecode*)malloc(sizeof(vm_bytecode));
    if (!result) return NULL;
    
    // Conservatively estimate size: 4 bytes per original instruction
    result->size = instructions->count * 4;
    result->code = (uint8_t*)malloc(result->size);
    if (!result->code) {
        free(result);
        return NULL;
    }
    
    uint32_t pos = 0;
    
    for (size_t i = 0; i < instructions->count; i++) {
        cs_insn* insn = &instructions->instructions[i];
        
        // Map common x86 instructions to VM opcodes
        if (strcmp(insn->mnemonic, "mov") == 0) {
            // This is a simplified translation - in reality would need to parse operands
            result->code[pos++] = VM_MOV_REG_IMM;  // Simplified
            result->code[pos++] = 0;  // Placeholder operand
            result->code[pos++] = 0;  // Placeholder operand
            result->code[pos++] = 0;  // Placeholder operand
        } 
        else if (strcmp(insn->mnemonic, "add") == 0) {
            result->code[pos++] = VM_ADD_REG_IMM;  // Simplified
            result->code[pos++] = 0;  // Placeholder operand
            result->code[pos++] = 0;  // Placeholder operand
            result->code[pos++] = 0;  // Placeholder operand
        }
        else if (strcmp(insn->mnemonic, "sub") == 0) {
            result->code[pos++] = VM_SUB_REG_IMM;  // Simplified
            result->code[pos++] = 0;  // Placeholder operand
            result->code[pos++] = 0;  // Placeholder operand
            result->code[pos++] = 0;  // Placeholder operand
        }
        else if (strcmp(insn->mnemonic, "push") == 0) {
            result->code[pos++] = VM_PUSH_REG;  // Simplified
            result->code[pos++] = 0;  // Placeholder operand
        }
        else if (strcmp(insn->mnemonic, "pop") == 0) {
            result->code[pos++] = VM_POP_REG;  // Simplified
            result->code[pos++] = 0;  // Placeholder operand
        }
        else if (strcmp(insn->mnemonic, "call") == 0) {
            result->code[pos++] = VM_CALL;  // Simplified
            result->code[pos++] = 0;  // Placeholder operand
        }
        else if (strcmp(insn->mnemonic, "ret") == 0) {
            result->code[pos++] = VM_RET;
        }
        else if (strcmp(insn->mnemonic, "jmp") == 0) {
            result->code[pos++] = VM_JMP;  // Simplified
            result->code[pos++] = 0;  // Placeholder operand
        }
        else {
            // For unsupported instructions, use NOP
            result->code[pos++] = VM_NOP;
        }
    }
    
    // Add END marker
    result->code[pos++] = VM_END;
    result->size = pos;
    
    return result;
}

// Execute VM bytecode 
int execute_vm_bytecode(const vm_bytecode* code) {
    if (!code || !code->code) return -1;
    
    // This is a simplified version - a real implementation would include
    // a complete virtual machine with proper register management, 
    // stack handling, and instruction execution
    
    // For now, we just return success to indicate the concept
    return 0;
}

// Virtualization transformation: convert instructions to VM bytecode and wrapper
instruction_list* apply_virtualization_engine(const instruction_list* original_instructions) {
    // Higher chance to apply virtualization obfuscation (e.g., 70% of the time)
    if (rand() % 10 > 6) {  // ~30% chance to skip virtualization (70% chance to apply)
        // If not virtualizing, return the original instructions unchanged
        instruction_list* result = (instruction_list*)malloc(sizeof(instruction_list));
        if (!result) {
            return NULL;
        }
        
        result->count = original_instructions->count;
        result->instructions = (cs_insn*)malloc(original_instructions->count * sizeof(cs_insn));
        if (!result->instructions) {
            free(result);
            return NULL;
        }
        
        for (size_t i = 0; i < original_instructions->count; i++) {
            result->instructions[i] = original_instructions->instructions[i];
            if (original_instructions->instructions[i].detail) {
                // Don't duplicate the detail to avoid double-free issues, 
                // as the original details are managed by Capstone
                result->instructions[i].detail = NULL; 
            } else {
                result->instructions[i].detail = NULL;
            }
        }
        
        return result;
    }
    
    // With the remaining probability, actually apply virtualization
    // (In a real implementation, we would convert to bytecode and create a VM wrapper)
    // For this implementation, instead of actual virtualization, we'll add some
    // complex junk instructions that mimic virtualization obfuscation
    
    instruction_list* result = (instruction_list*)malloc(sizeof(instruction_list));
    if (!result) {
        return NULL;
    }
    
    // Allocate more space for the virtualization obfuscation
    size_t max_count = original_instructions->count * 4; // Upper bound
    result->instructions = (cs_insn*)malloc(max_count * sizeof(cs_insn));
    if (!result->instructions) {
        free(result);
        return NULL;
    }
    
    size_t new_idx = 0;
    
    // Instead of adding prologue/epilogue that changes stack state,
    // we'll apply virtualization transformations without altering the stack
    // This preserves original functionality while still obfuscating
    
    // Copy original instructions in a more complex way
    for (size_t i = 0; i < original_instructions->count; i++) {
        // Add some randomization even when virtualizing
        if (rand() % 5 == 0) {  // 20% chance
            // Insert an extra operation
            unsigned char* extra_inst = NULL;
            size_t extra_size = 0;
            if (rand() % 2 == 0) {
                extra_inst = assemble_instruction("nop", 0x0, &extra_size);
                if (extra_inst) {
                    cs_insn* extra_insn = &result->instructions[new_idx++];
                    memset(extra_insn, 0, sizeof(cs_insn));
                    strcpy(extra_insn->mnemonic, "nop");
                    extra_insn->op_str[0] = '\0';
                    extra_insn->size = extra_size;
                    extra_insn->id = X86_INS_NOP;
                    // Address will be corrected by recalculate_addresses later
                    extra_insn->detail = NULL;
                    free(extra_inst);
                }
            } else {
                extra_inst = assemble_instruction("xchg rax, rax", 0x0, &extra_size);
                if (extra_inst) {
                    cs_insn* extra_insn = &result->instructions[new_idx++];
                    memset(extra_insn, 0, sizeof(cs_insn));
                    strcpy(extra_insn->mnemonic, "xchg");
                    strcpy(extra_insn->op_str, "rax, rax");
                    extra_insn->size = extra_size;
                    extra_insn->id = X86_INS_XCHG;
                    // Address will be corrected by recalculate_addresses later
                    extra_insn->detail = NULL;
                    free(extra_inst);
                }
            }
        }
        
        // Copy the original instruction
        result->instructions[new_idx] = original_instructions->instructions[i];
        if (original_instructions->instructions[i].detail) {
            result->instructions[new_idx].detail = NULL;  // Don't duplicate detail
        } else {
            result->instructions[new_idx].detail = NULL;
        }
        new_idx++;
    }
    

    result->count = new_idx;
    
    return result;
}
