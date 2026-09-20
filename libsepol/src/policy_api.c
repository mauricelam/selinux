#ifdef __EMSCRIPTEN__

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <emscripten.h>

/**
 * SELinux Policy Analysis Bridge for WebAssembly
 *
 * This file provides a simplified C API for interacting with the libsepol library.
 * It is intended to be compiled with Emscripten to allow the web-based filetool
 * to inspect and search compiled SELinux binary policy files.
 */

// Handle structure to wrap the libsepol policy database.
typedef struct {
    sepol_policydb_t *db;
} policy_handle_t;

/**
 * api_load_policy: Entry point to load a binary policy.
 *
 * Takes a pointer to binary data (usually from an ArrayBuffer in JS) and its length.
 * Initializes the libsepol environment and parses the binary image into a policydb.
 */
EMSCRIPTEN_KEEPALIVE
policy_handle_t* api_load_policy(void *data, size_t len) {
    sepol_policydb_t *db = NULL;
    sepol_policy_file_t *pf = NULL;

    // Allocate the policy database structure.
    if (sepol_policydb_create(&db) < 0) return NULL;

    // Create a policy file abstraction that libsepol uses for I/O.
    if (sepol_policy_file_create(&pf) < 0) {
        sepol_policydb_free(db);
        return NULL;
    }

    // Map the policy file abstraction to our memory buffer.
    sepol_policy_file_set_mem(pf, (char *)data, len);

    // Read the binary policy. This function handles format detection and parsing.
    if (sepol_policydb_read(db, pf) < 0) {
        sepol_policy_file_free(pf);
        sepol_policydb_free(db);
        return NULL;
    }

    // Clean up the temporary file abstraction.
    sepol_policy_file_free(pf);

    // Wrap the database in our handle and return to JS.
    policy_handle_t *h = malloc(sizeof(policy_handle_t));
    if (!h) {
        sepol_policydb_free(db);
        return NULL;
    }
    h->db = db;
    return h;
}

/**
 * api_free_policy: Cleanup function for loaded policies.
 */
EMSCRIPTEN_KEEPALIVE
void api_free_policy(policy_handle_t *h) {
    if (!h) return;
    // libsepol provides a deep-free function for the database.
    sepol_policydb_free(h->db);
    free(h);
}

/**
 * api_get_version: Returns the policy format version (e.g., 30 for Android).
 */
EMSCRIPTEN_KEEPALIVE
int api_get_version(policy_handle_t *h) {
    if (!h) return -1;
    // Access internal policy database structure to get the version.
    return ((struct sepol_policydb *)(h->db))->p.policyvers;
}

/**
 * api_get_symbol_count: Returns the number of entries for a given symbol type.
 *
 * sym_type maps to SYM_* constants in libsepol (e.g., 3 for Types, 2 for Roles).
 */
EMSCRIPTEN_KEEPALIVE
int api_get_symbol_count(policy_handle_t *h, int sym_type) {
    if (!h || sym_type < 0 || sym_type >= SYM_NUM) return -1;
    return ((struct sepol_policydb *)(h->db))->p.symtab[sym_type].nprim;
}

/**
 * api_get_symbol_name: Returns the string name of a symbol given its type and value.
 *
 * The value is the 1-based index used inside the policy's bitmask representations.
 */
EMSCRIPTEN_KEEPALIVE
const char* api_get_symbol_name(policy_handle_t *h, int sym_type, int value) {
    if (!h) return NULL;
    policydb_t *db = &((struct sepol_policydb *)(h->db))->p;
    if (sym_type < 0 || sym_type >= SYM_NUM) return NULL;
    // Indices in the names table are 0-based.
    if (value <= 0 || (uint32_t)value > db->symtab[sym_type].nprim) return NULL;
    return db->sym_val_to_name[sym_type][value - 1];
}

/**
 * api_is_type_attribute: Determines if a type ID refers to an Attribute.
 */
EMSCRIPTEN_KEEPALIVE
int api_is_type_attribute(policy_handle_t *h, int type_val) {
    if (!h) return -1;
    policydb_t *db = &((struct sepol_policydb *)(h->db))->p;
    if (type_val <= 0 || (uint32_t)type_val > db->p_types.nprim) return -1;

    // Get the type datum to check its flavor.
    type_datum_t *t = db->type_val_to_struct[type_val - 1];
    if (!t) return -1;

    return (t->flavor == TYPE_ATTRIB) ? 1 : 0;
}

/**
 * api_get_boolean_state: Returns the default runtime value of a policy boolean.
 */
EMSCRIPTEN_KEEPALIVE
int api_get_boolean_state(policy_handle_t *h, int bool_val) {
    if (!h) return -1;
    policydb_t *db = &((struct sepol_policydb *)(h->db))->p;
    if (bool_val <= 0 || (uint32_t)bool_val > db->p_bools.nprim) return -1;

    cond_bool_datum_t *b = db->bool_val_to_struct[bool_val - 1];
    if (!b) return -1;

    return b->state;
}

// State for rule counting traversal.
struct rule_count_state {
    uint16_t mask;
    int count;
};

/**
 * count_rules_by_mask: Traversal callback for counting rules matching a mask.
 */
static int count_rules_by_mask(avtab_key_t *k, avtab_datum_t *d, void *ptr) {
    struct rule_count_state *state = (struct rule_count_state *)ptr;
    if (k->specified & state->mask) {
        state->count++;
    }
    return 0;
}

/**
 * api_get_rule_count: Returns the number of rules matching the specified mask.
 */
EMSCRIPTEN_KEEPALIVE
int api_get_rule_count(policy_handle_t *h, uint16_t specified_mask) {
    if (!h) return -1;
    policydb_t *db = &((struct sepol_policydb *)(h->db))->p;
    struct rule_count_state state = { specified_mask, 0 };
    avtab_map(&db->te_avtab, count_rules_by_mask, &state);
    return state.count;
}

// Internal structure for returning rule information to the JS layer.
typedef struct {
    uint32_t src;
    uint32_t tgt;
    uint32_t cls;
    uint32_t data;
} rule_info_t;

// State tracking for the rule collection traversal.
struct rule_collect_state {
    policy_handle_t *handle;
    rule_info_t *rules;
    int index;
    int max;
    const char *query;
    int is_regex;
    regex_t *regex_compiled;
    uint16_t specified_mask;
};

/**
 * collect_rules: traversal callback for iterating the avtab.
 *
 * Checks if the rule matches the user's search query (if any) and
 * copies it into the results buffer.
 */
static int collect_rules(avtab_key_t *k, avtab_datum_t *d, void *ptr) {
    struct rule_collect_state *state = (struct rule_collect_state *)ptr;

    // Filter rules by the requested mask (Allow, Auditallow, etc.)
    if (!(k->specified & state->specified_mask)) return 0;
    if (state->index >= state->max) return 0;

    // If a search query is provided, check if either the source or target type names contain it.
    if (state->query && strlen(state->query) > 0) {
        const char *src_name = api_get_symbol_name(state->handle, SYM_TYPES, k->source_type);
        const char *tgt_name = api_get_symbol_name(state->handle, SYM_TYPES, k->target_type);
        const char *cls_name = api_get_symbol_name(state->handle, SYM_CLASSES, k->target_class);

        int match = 0;

        /**
         * Perform search using either POSIX regex or standard substring matching.
         * The search is applied to source type, target type, and security class names.
         */
        if (state->is_regex && state->regex_compiled) {
            // Regex matching: case-insensitive (based on regcomp flags in api_get_rules).
            if (src_name && regexec(state->regex_compiled, src_name, 0, NULL, 0) == 0) match = 1;
            if (!match && tgt_name && regexec(state->regex_compiled, tgt_name, 0, NULL, 0) == 0) match = 1;
            if (!match && cls_name && regexec(state->regex_compiled, cls_name, 0, NULL, 0) == 0) match = 1;
        } else {
            // Standard substring matching (default).
            if (src_name && strstr(src_name, state->query)) match = 1;
            if (!match && tgt_name && strstr(tgt_name, state->query)) match = 1;
            if (!match && cls_name && strstr(cls_name, state->query)) match = 1;
        }

        if (!match) return 0;
    }

    // Populate the result structure for JS to read from the WASM heap.
    state->rules[state->index].src = k->source_type;
    state->rules[state->index].tgt = k->target_type;
    state->rules[state->index].cls = k->target_class;
    state->rules[state->index].data = d->data;
    state->index++;
    return 0;
}

/**
 * api_get_rules: Searches and collects rules from the policy.
 *
 * Iterates through the entire Access Vector Table and filters rules based on 'query'
 * and 'specified_mask'. Matches are written to the 'out_rules' buffer up to 'max_rules'.
 * Supports both plain-text substring and POSIX extended regex matching.
 */
EMSCRIPTEN_KEEPALIVE
int api_get_rules(policy_handle_t *h, rule_info_t *out_rules, int max_rules, const char *query, int is_regex, uint16_t specified_mask) {
    if (!h) return -1;
    policydb_t *db = &((struct sepol_policydb *)(h->db))->p;
    regex_t regex;
    regex_t *regex_ptr = NULL;

    /**
     * If regex search is requested, compile the pattern once for the entire traversal
     * to ensure optimal performance when scanning thousands of rules.
     */
    if (is_regex && query && strlen(query) > 0) {
        // REG_EXTENDED for modern regex syntax, REG_ICASE for case-insensitivity,
        // and REG_NOSUB since we only care about a boolean match, not captures.
        if (regcomp(&regex, query, REG_EXTENDED | REG_ICASE | REG_NOSUB) == 0) {
            regex_ptr = &regex;
        } else {
            // If regex compilation fails (e.g. invalid syntax), fall back to standard
            // string matching for this search request.
            is_regex = 0;
        }
    }

    struct rule_collect_state state = { h, out_rules, 0, max_rules, query, is_regex, regex_ptr, specified_mask };

    // avtab_map is an efficient way to visit every node in the policy's internal hash table.
    avtab_map(&db->te_avtab, collect_rules, &state);

    // Clean up compiled regex resources if they were allocated.
    if (regex_ptr) {
        regfree(regex_ptr);
    }

    return state.index;
}

/**
 * api_get_permissions: Resolves an access vector bitmask to a human-readable string.
 *
 * Uses libsepol's sepol_av_to_string to convert the numeric 'data' field of a rule
 * into its constituent permission names for a given security class.
 */
EMSCRIPTEN_KEEPALIVE
char* api_get_permissions(policy_handle_t *h, int class_val, uint32_t data) {
    if (!h) return NULL;
    policydb_t *db = &((struct sepol_policydb *)(h->db))->p;
    if (class_val <= 0 || (uint32_t)class_val > db->p_classes.nprim) return NULL;
    return sepol_av_to_string(db, class_val, data);
}

/**
 * api_free_string: Frees a string allocated by the C library.
 *
 * Required for cleaning up strings returned by sepol_av_to_string.
 */
EMSCRIPTEN_KEEPALIVE
void api_free_string(char *s) {
    if (s) free(s);
}

#endif /* __EMSCRIPTEN__ */
