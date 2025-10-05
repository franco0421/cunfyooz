#include "disassembler.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <capstone/capstone.h>

instruction_list* disassemble(csh handle, const uint8_t* code, size_t size, uint64_t address) {
    cs_insn *insn;
    size_t count;

    // cs_open and cs_close are now managed by the caller (main)

    count = cs_disasm(handle, code, size, address, 0, &insn);
    if (count > 0) {
        instruction_list* list = (instruction_list*)malloc(sizeof(instruction_list));
        if (!list) {
            cs_free(insn, count);
            return NULL;
        }
        list->instructions = insn;
        list->count = count;
        return list;
    } else {
        fprintf(stderr, "Failed to disassemble code\n");
        return NULL;
    }
}

void free_instruction_list(instruction_list* list) {
    if (!list) {
        return;
    }
    if (list->instructions) {
        // Use Capstone's cs_free to handle all instruction data properly
        // This handles both the instructions and their details properly if they came from Capstone
        cs_free(list->instructions, list->count);
    }
    free(list);
}
