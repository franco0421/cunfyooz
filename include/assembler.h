#ifndef ASSEMBLER_H
#define ASSEMBLER_H

#include <stdint.h>
#include <stddef.h>
#include "disassembler.h"  // Include disassembler header to get instruction_list definition

// Assembles a single instruction.
// Returns the assembled code and its size.
// The caller is responsible for freeing the returned buffer.
unsigned char* assemble_instruction(const char* assembly, uint64_t address, size_t* size);

// Function to reassemble an entire instruction list into binary format
unsigned char* reassemble_instructions(const instruction_list* instructions, size_t* total_size);

#endif // ASSEMBLER_H
