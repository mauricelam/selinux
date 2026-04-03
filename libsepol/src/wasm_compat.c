#ifdef __EMSCRIPTEN__

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <sepol/policydb.h>
#include <cil/cil.h>

/* Forward declarations to satisfy -Wmissing-prototypes */
int sepol_compile_cil_to_binary(const char *cil_data, size_t cil_size, char **out_data, size_t *out_size);
int sepol_get_cil_ast(const char *cil_data, size_t cil_size, char **out_ast, size_t *out_size);

/* Emscripten's stdlib.h declares reallocarray but the library doesn't always
   provide it. We provide a non-static version here that matches the
   declaration in stdlib.h to avoid conflicts with the static inline
   definition in private.h. */
void* reallocarray(void *ptr, size_t nmemb, size_t size) {
	if (size && nmemb > (size_t)-1 / size) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(ptr, nmemb * size);
}

static void wasm_cil_log_handler(int lvl, const char *msg) {
	fprintf(stderr, "CIL [%d]: %s\n", lvl, msg);
}

/**
 * Compiles CIL source into a binary policy.
 *
 * @param cil_data The CIL source text.
 * @param cil_size The size of the CIL source text.
 * @param out_data Pointer to receive the allocated buffer for the binary policy.
 * @param out_size Pointer to receive the size of the binary policy.
 * @return 0 on success, -1 on failure.
 */
int sepol_compile_cil_to_binary(const char *cil_data, size_t cil_size, char **out_data, size_t *out_size) {
	cil_db_t *db = NULL;
	sepol_policydb_t *pd = NULL;
	int rc = -1;

	if (!cil_data || !out_data || !out_size) {
		return -1;
	}

	cil_set_log_handler(wasm_cil_log_handler);
	cil_set_log_level(CIL_INFO);

	cil_db_init(&db);
	if (!db) {
		goto exit;
	}

	rc = cil_add_file(db, "wasm_input.cil", cil_data, cil_size);
	if (rc != 0) {
		goto exit;
	}

	rc = cil_compile(db);
	if (rc != 0) {
		goto exit;
	}

	rc = cil_build_policydb(db, &pd);
	if (rc != 0) {
		goto exit;
	}

	/* Correctly use sepol_policydb_to_image to allocate and write the binary policy */
	rc = sepol_policydb_to_image(NULL, pd, (void **)out_data, out_size);

exit:
	if (pd) {
		sepol_policydb_free(pd);
	}
	if (db) {
		cil_db_destroy(&db);
	}
	return rc;
}

/**
 * Parses CIL source and returns the resolved AST as a string.
 * This is useful for "structured analysis" in the browser.
 *
 * @param cil_data The CIL source text.
 * @param cil_size The size of the CIL source text.
 * @param out_ast Pointer to receive the allocated string for the AST.
 * @param out_size Pointer to receive the size of the AST string.
 * @return 0 on success, -1 on failure.
 */
int sepol_get_cil_ast(const char *cil_data, size_t cil_size, char **out_ast, size_t *out_size) {
	cil_db_t *db = NULL;
	int rc = -1;
	FILE *mem_stream = NULL;

	if (!cil_data || !out_ast || !out_size) {
		return -1;
	}

	cil_db_init(&db);
	if (!db) {
		goto exit;
	}

	rc = cil_add_file(db, "wasm_input.cil", cil_data, cil_size);
	if (rc != 0) {
		goto exit;
	}

	/* Use cil_write_parse_ast if you want the AST from parsing,
	   but the user wants structured analysis, so resolved AST is better.
	   However, resolved AST requires cil_compile, which destroys the parse tree.
	   Wait, cil_write_resolve_ast also destroys the parse tree internally.
	*/

	mem_stream = open_memstream(out_ast, out_size);
	if (!mem_stream) {
		rc = -1;
		goto exit;
	}

	rc = cil_write_resolve_ast(mem_stream, db);
	fclose(mem_stream);

exit:
	if (db) {
		cil_db_destroy(&db);
	}
	return rc;
}

#endif /* __EMSCRIPTEN__ */
