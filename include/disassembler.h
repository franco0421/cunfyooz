#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include <stdint.h>
#include <stddef.h>
#include <capstone/capstone.h>

// A simple representation of a list of instructions
typedef struct _instruction_list {
    cs_insn* instructions;
    size_t count;
} instruction_list;

instruction_list* disassemble(csh handle, const uint8_t* code, size_t size, uint64_t address);
void free_instruction_list(instruction_list* list);

#endif // DISASSEMBLER_H
