// Package hexdump prints raw bytes in the classic "hexdump -C" style, so
// frames can be read by eye in the terminal while the stack runs.
//
// It sits beside the stack rather than in it: any layer can pass it a
// byte slice for logging. It only formats; it does not decode protocols.
package hexdump

import (
	"fmt"
	"io"
	"strings"
)

// Dump writes a classic hex+ASCII dump of b to w.
// Every line starts with prefix, then the offset of the line in hex, then
// 16 bytes in hex (split into two groups of 8), then the same bytes as
// ASCII between bars. For example:
//
//	0000  ff ff ff ff ff ff 02 00  00 00 00 01 08 06 00 01   |................|
//	0010  68 69                                              |hi|
//
// Bytes that are not printable ASCII are shown as '.'.
func Dump(w io.Writer, prefix string, b []byte) {
	const cols = 16
	for i := 0; i < len(b); i += cols {
		// The last line may hold fewer than 16 bytes.
		end := i + cols
		if end > len(b) {
			end = len(b)
		}
		chunk := b[i:end]

		var hexParts []string
		var ascii strings.Builder
		// Always emit 16 hex columns, blank ones on a short last line, so the
		// ASCII column lines up with the lines above it.
		for j := 0; j < cols; j++ {
			if j < len(chunk) {
				hexParts = append(hexParts, fmt.Sprintf("%02x", chunk[j]))
				// 0x20 (space) to 0x7e (~) is the printable ASCII range.
				c := chunk[j]
				if c < 0x20 || c > 0x7e {
					ascii.WriteByte('.')
				} else {
					ascii.WriteByte(c)
				}
			} else {
				hexParts = append(hexParts, "  ")
			}
			// An empty part after the 8th byte becomes an extra space when
			// joined, which splits the line into two groups of 8.
			if j == 7 {
				hexParts = append(hexParts, "")
			}
		}
		// 16 two-character columns plus 16 separating spaces always gives 48
		// characters; padding to 49 adds one more space before the ASCII.
		fmt.Fprintf(w, "%s%04x  %-49s  |%s|\n", prefix, i, strings.Join(hexParts, " "), ascii.String())
	}
}
