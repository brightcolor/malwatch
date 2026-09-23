package rules

import "bytes"

// Looks is what the first bytes of a file say it is, whatever its name.
//
// The name is what the web server goes by. The content is what PHP goes by
// once something includes the file, and a payload kept as .css, .txt or .ico
// and pulled in from elsewhere runs like any .php file. Rules that describe
// code therefore read a file by its content as well.
type Looks struct {
	// PHP means the file opens like a PHP file.
	PHP bool
	// Image means the file starts with the magic bytes of an image format.
	Image bool
}

// look inspects the start of content.
func look(content []byte) Looks {
	return Looks{PHP: startsLikePHP(content), Image: startsLikeImage(content)}
}

// startsLikePHP reports whether the file opens with a PHP tag.
//
// Only the start counts. PHP quoted in the middle of a text - an attack probe
// in a log, an example in a readme - is not code, and reading it as code made
// every such file a finding. A payload meant to be included opens with its tag,
// and one hidden behind image bytes is the image rules' business.
func startsLikePHP(b []byte) bool {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	if bytes.HasPrefix(b, []byte("#!")) {
		// A command line script: #!/usr/bin/env php, then the tag.
		nl := bytes.IndexByte(b, '\n')
		if nl < 0 {
			return false
		}
		b = b[nl+1:]
	}
	b = bytes.TrimLeft(b, " \t\r\n")
	if len(b) < 3 || b[0] != '<' || b[1] != '?' {
		return false
	}
	rest := b[2:]
	switch {
	case rest[0] == '=':
		return true
	case rest[0] == ' ' || rest[0] == '\t' || rest[0] == '\r' || rest[0] == '\n':
		return true
	case len(rest) >= 3 && bytes.EqualFold(rest[:3], []byte("php")):
		// <?php must not run on into a longer name.
		return len(rest) == 3 || !isNameByte(rest[3])
	}
	return false
}

// startsLikeImage reports whether the file carries the magic bytes of an
// image format a website serves.
func startsLikeImage(b []byte) bool {
	switch {
	case bytes.HasPrefix(b, []byte("\xff\xd8\xff")): // JPEG
		return true
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return true
	case bytes.HasPrefix(b, []byte("GIF87a")), bytes.HasPrefix(b, []byte("GIF89a")):
		return true
	case len(b) >= 12 && bytes.Equal(b[:4], []byte("RIFF")) && bytes.Equal(b[8:12], []byte("WEBP")):
		return true
	case len(b) >= 14 && b[0] == 'B' && b[1] == 'M' && b[6] == 0 && b[7] == 0 && b[8] == 0 && b[9] == 0:
		// BMP. "BM" alone opens plenty of text; the four reserved bytes of
		// the header are zero in every real bitmap.
		return true
	case len(b) >= 6 && b[0] == 0 && b[1] == 0 && (b[2] == 1 || b[2] == 2) && b[3] == 0 && (b[4] != 0 || b[5] != 0):
		// ICO and CUR, with at least one picture in the directory.
		return true
	case bytes.HasPrefix(b, []byte("II*\x00")), bytes.HasPrefix(b, []byte("MM\x00*")): // TIFF
		return true
	case len(b) >= 12 && bytes.Equal(b[4:8], []byte("ftyp")):
		// AVIF and HEIC share the container of MP4; the brand tells them apart.
		switch string(b[8:12]) {
		case "avif", "avis", "heic", "heix", "mif1", "msf1":
			return true
		}
	}
	return false
}
