#ifndef ALOSINT_JSON_WRITER_H
#define ALOSINT_JSON_WRITER_H

/*
 * alosint_json_escape — escape a C string for embedding inside a JSON
 * double-quoted string (the surrounding quotes are NOT written).
 *
 * Escaping rules:
 *   "  -> \"      \  -> \\      \n -> \n     \r -> \r
 *   \t -> \t      \b -> \b      \f -> \f
 *   other control bytes < 0x20  -> \u00XX   (lowercase hex)
 *   every other byte (including UTF-8 continuation bytes) passes through.
 *
 * The result is always NUL-terminated. At most max_len bytes are written to
 * out, counting the terminator; if the escaped form does not fit, output stops
 * on a whole escape boundary (never a partial sequence) and out is terminated
 * at or before out[max_len-1].
 *
 * Parameters:
 *   in       NUL-terminated input (borrowed, read-only).
 *   out      caller-owned destination buffer.
 *   max_len  capacity of out in bytes, including the terminating NUL.
 *
 * Returns:
 *   >=0  the number of bytes written to out, excluding the NUL terminator.
 *   -1   if in is NULL, out is NULL, or max_len <= 0.
 */
int alosint_json_escape(const char *in, char *out, int max_len);

/*
 * alosint_json_escape_len — worst-case size, in bytes, of the buffer needed to
 * escape `in` with alosint_json_escape, including the NUL terminator
 * (6 * strlen(in) + 1). Writes nothing.
 *
 * Returns the required size, or -1 if `in` is NULL or the size would not fit
 * in an int.
 */
int alosint_json_escape_len(const char *in);

#endif /* ALOSINT_JSON_WRITER_H */
