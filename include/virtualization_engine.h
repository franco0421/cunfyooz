#ifndef VIRTUALIZATION_ENGINE_H
#define VIRTUALIZATION_ENGINE_H

#include "disassembler.h"

// VM bytecode structure
typedef struct {
    uint8_t* code;
    uint32_t size;
} vm_bytecode;

// Function to apply virtualization engine transformation
instruction_list* apply_virtualization_engine(const instruction_list* original_instructions);

#endif // VIRTUALIZATION_ENGINE_H