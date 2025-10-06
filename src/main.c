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

#include "json_parser.h"
#include <sys/wait.h>

// Function to validate that transformed executable behaves the same as original
int validate_transformation(const char* original_file, const char* transformed_file) {
    // For now, we'll implement a basic validation by running both and comparing output
    // In a complete implementation, we'd want more sophisticated checks
    
    char original_cmd[512], transformed_cmd[512];
    char original_output[256], transformed_output[256];
    
    // Run original executable and capture output
    snprintf(original_cmd, sizeof(original_cmd), "wine %s 2>/dev/null", original_file);
    FILE* orig_fp = popen(original_cmd, "r");
    if (!orig_fp) {
        fprintf(stderr, "Failed to run original executable for validation\n");
        return -1;
    }
    
    if (fgets(original_output, sizeof(original_output), orig_fp) == NULL) {
        // Handle case where no output is generated
        original_output[0] = '\0';
    }
    pclose(orig_fp);
    
    // Run transformed executable and capture output
    snprintf(transformed_cmd, sizeof(transformed_cmd), "wine %s 2>/dev/null", transformed_file);
    FILE* trans_fp = popen(transformed_cmd, "r");
    if (!trans_fp) {
        fprintf(stderr, "Failed to run transformed executable for validation\n");
        return -1;
    }
    
    if (fgets(transformed_output, sizeof(transformed_output), trans_fp) == NULL) {
        // Handle case where no output is generated
        transformed_output[0] = '\0';
    }
    pclose(trans_fp);
    
    // Compare outputs, handling potential line ending differences
    size_t orig_len = strlen(original_output);
    size_t trans_len = strlen(transformed_output);
    
    // Remove potential \r\n or \n at the end of both strings
    if (orig_len > 0 && original_output[orig_len - 1] == '\n') {
        original_output[orig_len - 1] = '\0';
        orig_len--;
        if (orig_len > 0 && original_output[orig_len - 1] == '\r') {
            original_output[orig_len - 1] = '\0';
        }
    }
    
    if (trans_len > 0 && transformed_output[trans_len - 1] == '\n') {
        transformed_output[trans_len - 1] = '\0';
        trans_len--;
        if (trans_len > 0 && transformed_output[trans_len - 1] == '\r') {
            transformed_output[trans_len - 1] = '\0';
        }
    }
    
    // If outputs match, transformation is valid
    return strcmp(original_output, transformed_output) == 0 ? 1 : 0;
}

int main(int argc, char *argv[]) {
    // Initialize random seed for metamorphic operations
    srand((unsigned int)time(NULL) + clock());
    
    config_t* config = NULL;
    FILE* config_file = fopen("config.json", "r");
    if (config_file) {
        fseek(config_file, 0, SEEK_END);
        long length = ftell(config_file);
        fseek(config_file, 0, SEEK_SET);
        char* buffer = (char*)malloc(length + 1);
        if (buffer) {
            fread(buffer, 1, length, config_file);
            buffer[length] = '\0';
            config = parse_json_config(buffer);
            free(buffer);
        }
        fclose(config_file);
    }

    if (!config) {
        // Create default config if file doesn't exist or parsing fails
        config = (config_t*)malloc(sizeof(config_t));
        if (config) {
            config->transformations.nop_insertion.enabled = true;
            config->transformations.instruction_substitution.enabled = true;
            config->transformations.register_shuffling.enabled = true;
            config->transformations.enhanced_nop_insertion.enabled = true;
            config->transformations.control_flow_obfuscation.enabled = true;
            config->transformations.stack_frame_obfuscation.enabled = true;
            config->transformations.instruction_reordering.enabled = true;
            config->transformations.anti_analysis_techniques.enabled = true;
            config->transformations.virtualization_engine.enabled = false; // Disabled by default
            
            // Set default security settings
            config->security.validate_functionality = true;
            config->security.preserve_original_behavior = true;
        }
    }

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

    instruction_list* transformed_instructions = original_instructions;
    instruction_list* to_free = NULL;  // Keep track of intermediate results to free

    if (config && config->transformations.nop_insertion.enabled) {
        instruction_list* next_instructions = apply_nop_insertion(transformed_instructions);
        if (transformed_instructions != original_instructions) {
            // If this isn't the original list, it's an intermediate result we need to free later
            if (to_free) free_instruction_list(to_free);
            to_free = transformed_instructions;
        }
        transformed_instructions = next_instructions;
        recalculate_addresses(transformed_instructions);
    }
    if (config && config->transformations.instruction_substitution.enabled) {
        instruction_list* next_instructions = apply_instruction_substitution(transformed_instructions, handle);
        if (transformed_instructions != original_instructions) {
            // If this isn't the original list, it's an intermediate result we need to free later
            if (to_free) free_instruction_list(to_free);
            to_free = transformed_instructions;
        }
        transformed_instructions = next_instructions;
        recalculate_addresses(transformed_instructions);
    }
    if (config && config->transformations.register_shuffling.enabled) {
        instruction_list* next_instructions = apply_register_shuffling(transformed_instructions, handle);
        if (transformed_instructions != original_instructions) {
            // If this isn't the original list, it's an intermediate result we need to free later
            if (to_free) free_instruction_list(to_free);
            to_free = transformed_instructions;
        }
        transformed_instructions = next_instructions;
        recalculate_addresses(transformed_instructions);
    }
    if (config && config->transformations.enhanced_nop_insertion.enabled) {
        instruction_list* next_instructions = apply_enhanced_nop_insertion(transformed_instructions);
        if (transformed_instructions != original_instructions) {
            // If this isn't the original list, it's an intermediate result we need to free later
            if (to_free) free_instruction_list(to_free);
            to_free = transformed_instructions;
        }
        transformed_instructions = next_instructions;
        recalculate_addresses(transformed_instructions);
    }
    if (config && config->transformations.control_flow_obfuscation.enabled) {
        instruction_list* next_instructions = apply_control_flow_obfuscation(transformed_instructions);
        if (transformed_instructions != original_instructions) {
            // If this isn't the original list, it's an intermediate result we need to free later
            if (to_free) free_instruction_list(to_free);
            to_free = transformed_instructions;
        }
        transformed_instructions = next_instructions;
        recalculate_addresses(transformed_instructions);
    }
    if (config && config->transformations.stack_frame_obfuscation.enabled) {
        instruction_list* next_instructions = apply_stack_frame_obfuscation(transformed_instructions);
        if (transformed_instructions != original_instructions) {
            // If this isn't the original list, it's an intermediate result we need to free later
            if (to_free) free_instruction_list(to_free);
            to_free = transformed_instructions;
        }
        transformed_instructions = next_instructions;
        recalculate_addresses(transformed_instructions);
    }
    if (config && config->transformations.instruction_reordering.enabled) {
        instruction_list* next_instructions = apply_instruction_reordering(transformed_instructions);
        if (transformed_instructions != original_instructions) {
            // If this isn't the original list, it's an intermediate result we need to free later
            if (to_free) free_instruction_list(to_free);
            to_free = transformed_instructions;
        }
        transformed_instructions = next_instructions;
        recalculate_addresses(transformed_instructions);
    }
    if (config && config->transformations.anti_analysis_techniques.enabled) {
        instruction_list* next_instructions = apply_anti_analysis_techniques(transformed_instructions);
        if (transformed_instructions != original_instructions) {
            // If this isn't the original list, it's an intermediate result we need to free later
            if (to_free) free_instruction_list(to_free);
            to_free = transformed_instructions;
        }
        transformed_instructions = next_instructions;
        recalculate_addresses(transformed_instructions);
    }
    if (config && config->transformations.virtualization_engine.enabled) {
        instruction_list* next_instructions = apply_virtualization_engine(transformed_instructions);
        if (transformed_instructions != original_instructions) {
            // If this isn't the original list, it's an intermediate result we need to free later
            if (to_free) free_instruction_list(to_free);
            to_free = transformed_instructions;
        }
        transformed_instructions = next_instructions;
        recalculate_addresses(transformed_instructions);
    }

    // Reassemble transformed instructions back into binary format
    size_t reassembled_size;
    unsigned char* reassembled_code = reassemble_instructions(transformed_instructions, &reassembled_size);
    if (!reassembled_code) {
        fprintf(stderr, "Failed to reassemble transformed instructions.\n");
        if (transformed_instructions != original_instructions) free_instruction_list(transformed_instructions);
        free_instruction_list(original_instructions);
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
        if (transformed_instructions != original_instructions) free_instruction_list(transformed_instructions);
        free_instruction_list(original_instructions);
        free_pe_info(pe);
        cs_close(&handle);
        return 1;
    }
    
    // If validation is enabled in the config, check that the transformed executable behaves the same as the original
    if (config && config->security.validate_functionality) {
        printf("Validating transformed executable functionality...\n");
        int validation_result = validate_transformation(filepath, output_filename);
        
        if (validation_result == -1) {
            fprintf(stderr, "Validation failed: Could not run executables for comparison\n");
        } else if (validation_result == 0) {
            fprintf(stderr, "Validation failed: Transformed executable produces different output than original\n");
            
            // Remove the invalid transformed file
            remove(output_filename);
            
            // Clean up resources
            free(reassembled_code);
            free_instruction_list(transformed_instructions);
            free_instruction_list(original_instructions);
            if (to_free && to_free != transformed_instructions && to_free != original_instructions) {
                free_instruction_list(to_free);
            }
            free_pe_info(pe);
            cs_close(&handle);
            if (config) free(config);
            return 1;
        } else {
            printf("Validation passed: Transformed executable produces same output as original\n");
        }
    }
    
    printf("Successfully wrote transformed PE file to: %s\n", output_filename);

    // Clean up
    free(reassembled_code);
    free_instruction_list(original_instructions);
    if (transformed_instructions != original_instructions) {
        free_instruction_list(transformed_instructions);
    }
    if (to_free && to_free != transformed_instructions && to_free != original_instructions) {
        free_instruction_list(to_free);
    }
    free_pe_info(pe);
    cs_close(&handle);
    if (config) free(config);

    return 0;

    return 0;
}
