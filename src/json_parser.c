#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "json_parser.h"

// Forward declarations for parsing functions
static const char* parse_value(config_t* config, const char* json_string, const char* parent_key, const char* key);
static const char* parse_object(config_t* config, const char* json_string, const char* parent_key);

config_t* parse_json_config(const char* json_string) {
    config_t* config = (config_t*)calloc(1, sizeof(config_t));
    if (!config) {
        fprintf(stderr, "Failed to allocate memory for config.\n");
        return NULL;
    }

    const char* current_pos = json_string;
    current_pos = strchr(current_pos, '{');
    if (!current_pos) {
        fprintf(stderr, "Invalid JSON format: missing opening brace.\n");
        free(config);
        return NULL;
    }

    current_pos = parse_object(config, current_pos + 1, NULL);

    if (!current_pos) {
        fprintf(stderr, "Failed to parse JSON object.\n");
        free(config);
        return NULL;
    }

    return config;
}

static const char* parse_object(config_t* config, const char* json_string, const char* parent_key) {
    const char* current_pos = json_string;
    while (current_pos && *current_pos != '}') {
        const char* key_start = strchr(current_pos, '"');
        if (!key_start) break;

        const char* key_end = strchr(key_start + 1, '"');
        if (!key_end) {
            fprintf(stderr, "Invalid JSON format: unterminated key string.\n");
            return NULL;
        }

        int key_len = key_end - (key_start + 1);
        char key[64];
        if (key_len > (int)sizeof(key) - 1) key_len = (int)sizeof(key) - 1;
        strncpy(key, key_start + 1, key_len);
        key[key_len] = '\0';

        const char* colon = strchr(key_end, ':');
        if (!colon) {
            fprintf(stderr, "Invalid JSON format: missing colon after key.\n");
            return NULL;
        }

        current_pos = parse_value(config, colon + 1, parent_key, key);

        // Find next comma or closing brace
        const char* next_token = strchr(current_pos, ',');
        if (next_token && *(next_token + 1) != '}') {
            current_pos = next_token + 1;
        } else {
            current_pos = strchr(current_pos, '}');
        }
    }
    return current_pos ? current_pos + 1 : NULL;
}

static void set_config_value(config_t* config, const char* transform_key, const char* property_key, long value) {
    transformation_property_t* t_config = NULL;
    if (strcmp(transform_key, "nop_insertion") == 0) t_config = &config->transformations.nop_insertion;
    else if (strcmp(transform_key, "instruction_substitution") == 0) t_config = &config->transformations.instruction_substitution;
    else if (strcmp(transform_key, "register_shuffling") == 0) t_config = &config->transformations.register_shuffling;
    else if (strcmp(transform_key, "enhanced_nop_insertion") == 0) t_config = &config->transformations.enhanced_nop_insertion;
    else if (strcmp(transform_key, "control_flow_obfuscation") == 0) t_config = &config->transformations.control_flow_obfuscation;
    else if (strcmp(transform_key, "stack_frame_obfuscation") == 0) t_config = &config->transformations.stack_frame_obfuscation;
    else if (strcmp(transform_key, "instruction_reordering") == 0) t_config = &config->transformations.instruction_reordering;
    else if (strcmp(transform_key, "anti_analysis_techniques") == 0) t_config = &config->transformations.anti_analysis_techniques;
    else if (strcmp(transform_key, "virtualization_engine") == 0) t_config = &config->transformations.virtualization_engine;

    if (t_config) {
        if (strcmp(property_key, "enabled") == 0) t_config->enabled = (bool)value;
        else if (strcmp(property_key, "probability") == 0) t_config->probability = (int)value;
    }
}


static const char* parse_value(config_t* config, const char* json_string, const char* parent_key, const char* key) {
    const char* current_pos = json_string;
    while (isspace(*current_pos)) current_pos++;

    if (*current_pos == '{') {
        return parse_object(config, current_pos + 1, key);
    } else if (strncmp(current_pos, "true", 4) == 0) {
        if (parent_key) set_config_value(config, parent_key, key, 1);
        return current_pos + 4;
    } else if (strncmp(current_pos, "false", 5) == 0) {
        if (parent_key) set_config_value(config, parent_key, key, 0);
        return current_pos + 5;
    } else if (isdigit(*current_pos)) {
        char* end_ptr;
        long val = strtol(current_pos, &end_ptr, 10);
        if (parent_key) set_config_value(config, parent_key, key, val);
        return end_ptr;
    }

    return current_pos;
}
