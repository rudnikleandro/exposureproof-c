#include "text.h"

/* Everything printed here comes from servers the investigated party may
 * control, so control bytes (terminal escape sequences, embedded NULs) are
 * replaced before they reach the analyst's terminal. */
void sanitize_text(char *text, size_t length, int keep_newlines)
{
    for (size_t i = 0; i < length; i++)
    {
        unsigned char byte = (unsigned char)text[i];

        if (keep_newlines &&
            (byte == '\n' || byte == '\t' || (byte == '\r' && i + 1 < length && text[i + 1] == '\n')))
        {
            continue;
        }

        if (byte < 0x20 || byte == 0x7f)
        {
            text[i] = '?';
        }
    }
}
