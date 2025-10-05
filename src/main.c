#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <capstone/capstone.h>

#include "pe_parser.h"
#include "disassembler.h"
#include "transformer.h"
#include "assembler.h"

int main(int argc, char *argv[]) {
    // Initialize random seed for metamorphic operations
    srand((unsigned int)time(NULL) + clock());
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <executable_path>\n", argv[0]);
        return 1;
    }

    const char *filepath = argv[1];
    uint8_t *code = NULL;
    size_t code_size = 0;
    uint64_t base_address = 0;

    // Initialize Capstone
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone\n");
        return 1;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // Enable detail for operands

    // For simplicity, let's assume it's a PE file for now and extract code section
    // In a real scenario, you'd detect file type (ELF, PE, etc.)
    pe_info *pe = parse_pe(filepath);
    if (!pe) {
        fprintf(stderr, "Failed to parse PE file or not a PE file.\n");
        cs_close(&handle);
        return 1;
    }

    // Assuming .text section contains executable code
    for (int i = 0; i < pe->num_sections; i++) {
        if (strcmp((char*)pe->sections[i].name, ".text") == 0) {
            code = pe->sections[i].data;
            code_size = pe->sections[i].size;
            base_address = pe->sections[i].virtual_address;
            break;
        }
    }

    if (!code || code_size == 0) {
        fprintf(stderr, "Could not find .text section or it's empty.\n");
        free_pe_info(pe);
        cs_close(&handle);
        return 1;
    }

    instruction_list* original_instructions = disassemble(handle, code, code_size, base_address);
    if (!original_instructions) {
        fprintf(stderr, "Failed to disassemble code.\n");
        free_pe_info(pe);
        cs_close(&handle);
        return 1;
    }

    printf("Original Instructions:\n");
    for (size_t i = 0; i < original_instructions->count; i++) {
        cs_insn* insn = &original_instructions->instructions[i];
        printf("0x%"PRIx64":\t%s\t%s\n", insn->address, insn->mnemonic, insn->op_str);
    }
    fflush(stdout);

    // Apply NOP insertion
    instruction_list* nop_transformed_instructions = apply_nop_insertion(original_instructions);
    if (!nop_transformed_instructions) {
        fprintf(stderr, "NOP insertion failed.\n");
        free_instruction_list(original_instructions);
        free_pe_info(pe);
        cs_close(&handle);
        return 1;
    }
    printf("\nNOP Transformed Instructions:\n");
    for (size_t i = 0; i < nop_transformed_instructions->count; i++) {
        cs_insn* insn = &nop_transformed_instructions->instructions[i];
        printf("0x%"PRIx64":\t%s\t%s\n", insn->address, insn->mnemonic, insn->op_str);
    }
    fflush(stdout);
    free_instruction_list(original_instructions);

    // Apply instruction substitution
    instruction_list* substituted_instructions = apply_instruction_substitution(nop_transformed_instructions, handle);
    recalculate_addresses(substituted_instructions);
    if (!substituted_instructions) {
        fprintf(stderr, "Instruction substitution failed (substituted_instructions is NULL).\n");
        free_instruction_list(nop_transformed_instructions);
        free_pe_info(pe);
        cs_close(&handle);
        return 1;
    }
    printf("\nSubstituted Instructions:\n");
    for (size_t i = 0; i < substituted_instructions->count; i++) {
        cs_insn* insn = &substituted_instructions->instructions[i];
        printf("0x%"PRIx64":\t%s\t%s\n", insn->address, insn->mnemonic, insn->op_str);
    }
    fflush(stdout);
    free_instruction_list(nop_transformed_instructions);

    // Apply register shuffling
    instruction_list* shuffled_instructions = apply_register_shuffling(substituted_instructions, handle);
    recalculate_addresses(shuffled_instructions);
    if (!shuffled_instructions) {
        fprintf(stderr, "Register shuffling failed.\n");
        free_instruction_list(substituted_instructions);
        free_pe_info(pe);
        cs_close(&handle);
        return 1;
    }
    printf("\nShuffled Instructions:\n");
    for (size_t i = 0; i < shuffled_instructions->count; i++) {
        cs_insn* insn = &shuffled_instructions->instructions[i];
        printf("0x%"PRIx64":\t%s\t%s\n", insn->address, insn->mnemonic, insn->op_str);
    }
    fflush(stdout);
    free_instruction_list(substituted_instructions);

    // Apply enhanced NOP insertion
    instruction_list* enhanced_nop_instructions = apply_enhanced_nop_insertion(shuffled_instructions);
    recalculate_addresses(enhanced_nop_instructions);
    if (!enhanced_nop_instructions) {
        fprintf(stderr, "Enhanced NOP insertion failed.\n");
        free_instruction_list(shuffled_instructions);
        free_pe_info(pe);
        cs_close(&handle);
        return 1;
    }
    printf("\nEnhanced NOP Instructions:\n");
    for (size_t i = 0; i < enhanced_nop_instructions->count; i++) {
        cs_insn* insn = &enhanced_nop_instructions->instructions[i];
        printf("0x%"PRIx64":\t%s\t%s\n", insn->address, insn->mnemonic, insn->op_str);
    }
    fflush(stdout);
    free_instruction_list(shuffled_instructions);

    // Apply control flow obfuscation
    instruction_list* cfo_instructions = apply_control_flow_obfuscation(enhanced_nop_instructions);
    recalculate_addresses(cfo_instructions);
    if (!cfo_instructions) {
        fprintf(stderr, "Control flow obfuscation failed.\n");
        free_instruction_list(enhanced_nop_instructions);
        free_pe_info(pe);
        cs_close(&handle);
        return 1;
    }
    printf("\nControl Flow Obfuscated Instructions:\n");
    for (size_t i = 0; i < cfo_instructions->count; i++) {
        cs_insn* insn = &cfo_instructions->instructions[i];
        printf("0x%"PRIx64":\t%s\t%s\n", insn->address, insn->mnemonic, insn->op_str);
    }
    fflush(stdout);
    free_instruction_list(enhanced_nop_instructions);

    // Apply stack frame obfuscation
    instruction_list* sfo_instructions = apply_stack_frame_obfuscation(cfo_instructions);
    recalculate_addresses(sfo_instructions);
    if (!sfo_instructions) {
        fprintf(stderr, "Stack frame obfuscation failed.\n");
        free_instruction_list(cfo_instructions);
        free_pe_info(pe);
        cs_close(&handle);
        return 1;
    }
    printf("\nStack Frame Obfuscated Instructions:\n");
    for (size_t i = 0; i < sfo_instructions->count; i++) {
        cs_insn* insn = &sfo_instructions->instructions[i];
        printf("0x%"PRIx64":\t%s\t%s\n", insn->address, insn->mnemonic, insn->op_str);
    }
    fflush(stdout);
    free_instruction_list(cfo_instructions);

    // Apply instruction reordering
    instruction_list* reordered_instructions = apply_instruction_reordering(sfo_instructions);
    recalculate_addresses(reordered_instructions);
    if (!reordered_instructions) {
        fprintf(stderr, "Instruction reordering failed.\n");
        free_instruction_list(sfo_instructions);
        free_pe_info(pe);
        cs_close(&handle);
        return 1;
    }
    printf("\nReordered Instructions:\n");
    for (size_t i = 0; i < reordered_instructions->count; i++) {
        cs_insn* insn = &reordered_instructions->instructions[i];
        printf("0x%"PRIx64":\t%s\t%s\n", insn->address, insn->mnemonic, insn->op_str);
    }
    fflush(stdout);
    free_instruction_list(sfo_instructions);

    // Apply anti-analysis techniques
    instruction_list* anti_analysis_instructions = apply_anti_analysis_techniques(reordered_instructions);
    recalculate_addresses(anti_analysis_instructions);
    if (!anti_analysis_instructions) {
        fprintf(stderr, "Anti-analysis techniques failed.\n");
        free_instruction_list(reordered_instructions);
        free_pe_info(pe);
        cs_close(&handle);
        return 1;
    }
    printf("\nAnti-Analysis Instructions:\n");
    for (size_t i = 0; i < anti_analysis_instructions->count; i++) {
        cs_insn* insn = &anti_analysis_instructions->instructions[i];
        printf("0x%"PRIx64":\t%s\t%s\n", insn->address, insn->mnemonic, insn->op_str);
    }
    fflush(stdout);
    free_instruction_list(reordered_instructions);

    // Apply virtualization engine
    instruction_list* virtualized_instructions = apply_virtualization_engine(anti_analysis_instructions);
    recalculate_addresses(virtualized_instructions);
    if (!virtualized_instructions) {
        fprintf(stderr, "Virtualization engine failed.\n");
        free_instruction_list(anti_analysis_instructions);
        free_pe_info(pe);
        cs_close(&handle);
        return 1;
    }
    printf("\nVirtualized Instructions:\n");
    for (size_t i = 0; i < virtualized_instructions->count; i++) {
        cs_insn* insn = &virtualized_instructions->instructions[i];
        printf("0x%"PRIx64":\t%s\t%s\n", insn->address, insn->mnemonic, insn->op_str);
    }
    fflush(stdout);
    free_instruction_list(anti_analysis_instructions);

    // Reassemble transformed instructions back into binary format
    size_t reassembled_size;
    unsigned char* reassembled_code = reassemble_instructions(virtualized_instructions, &reassembled_size);
    if (!reassembled_code) {
        fprintf(stderr, "Failed to reassemble transformed instructions.\n");
        free_instruction_list(virtualized_instructions);
        free_pe_info(pe);
        cs_close(&handle);
        return 1;
    }
    printf("\nReassembled code size: %zu bytes\n", reassembled_size);

    // Generate output filename - prepend "cunfyoozed_" to the original filename
    char output_filename[512];
    
    // Find the last occurrence of path separator to extract directory path
    const char* last_sep = strrchr(filepath, '/');
    if (!last_sep) {
        last_sep = strrchr(filepath, '\\');  // Windows-style path as well
    }
    
    if (last_sep) {
        // Copy the directory part
        size_t dir_len = last_sep - filepath + 1; // +1 to include the separator
        strncpy(output_filename, filepath, dir_len);
        output_filename[dir_len] = '\0';
        
        // Add "cunfyoozed_" prefix to the basename part
        strcat(output_filename, "cunfyoozed_");
        strcat(output_filename, last_sep + 1); // The filename after separator
    } else {
        // No directory path, just filename
        snprintf(output_filename, sizeof(output_filename), "cunfyoozed_%s", filepath);
    }
    
    // Write the transformed PE file
    int write_result = write_transformed_pe(pe, reassembled_code, reassembled_size, output_filename);
    if (write_result != 0) {
        fprintf(stderr, "Failed to write transformed PE file.\n");
        free(reassembled_code);
        free_instruction_list(virtualized_instructions);
        free_pe_info(pe);
        cs_close(&handle);
        return 1;
    }
    printf("Successfully wrote transformed PE file to: %s\n", output_filename);

    // Clean up
    free(reassembled_code);
    free_instruction_list(virtualized_instructions);

    return 0;
}
