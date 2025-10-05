#ifndef TRANSFORMER_H
#define TRANSFORMER_H

#include "disassembler.h"
#include "virtualization_engine.h"
#include <stdbool.h>

// Structure to hold transformation properties
typedef struct {
    bool enabled;
    int probability;
} transformation_property_t;

// Structure to hold configuration for all transformations
typedef struct {
    struct {
        transformation_property_t nop_insertion;
        transformation_property_t instruction_substitution;
        transformation_property_t register_shuffling;
        transformation_property_t enhanced_nop_insertion;
        transformation_property_t control_flow_obfuscation;
        transformation_property_t stack_frame_obfuscation;
        transformation_property_t instruction_reordering;
        transformation_property_t anti_analysis_techniques;
        transformation_property_t virtualization_engine;
    } transformations;
} config_t;

// Function to apply a NOP insertion transformation
instruction_list* apply_nop_insertion(const instruction_list* original_instructions);

instruction_list* apply_instruction_substitution(const instruction_list* original_instructions, csh handle);
instruction_list* apply_register_shuffling(const instruction_list* original_instructions, csh handle);

// Enhanced transformation functions
instruction_list* apply_enhanced_nop_insertion(const instruction_list* original_instructions);
instruction_list* apply_control_flow_obfuscation(const instruction_list* original_instructions);
instruction_list* apply_stack_frame_obfuscation(const instruction_list* original_instructions);
instruction_list* apply_instruction_reordering(const instruction_list* original_instructions);
instruction_list* apply_anti_analysis_techniques(const instruction_list* original_instructions);
instruction_list* apply_virtualization_engine(const instruction_list* original_instructions);

// Utility functions
void recalculate_addresses(instruction_list* instructions);

#endif // TRANSFORMER_H
