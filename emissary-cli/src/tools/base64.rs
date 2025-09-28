// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Base64 encode/decode files and strings using the I2P Base64 alphabet.

use anyhow::anyhow;
use emissary_core::crypto::{base64_decode, base64_encode};

use std::{
    fs,
    io::{self, Read, Write},
};

/// Base64-encode data from `string`, `file` or stdin based on which is specified and write the
/// Base64-encoded string to `output` (if specified) or to stdout.
pub fn encode(
    string: Option<String>,
    file: Option<String>,
    output: Option<String>,
) -> anyhow::Result<()> {
    // clap has ensured that only `string` or `file` is `Some` but not both
    let encoded = match (string, file) {
        (Some(string), _) => base64_encode(string),
        (_, Some(path)) => base64_encode(fs::read(path)?),
        (None, None) => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            base64_encode(buf)
        }
    };

    if let Some(out) = output {
        fs::write(out, encoded)?;
    } else {
        io::stdout().write_all(encoded.as_ref())?;
    }

    Ok(())
}

/// Base64-decode data from `string`, `file` or stdin based on which is specified and write the
/// Base64-encoded string to `output` (if specified) or to stdout.
pub fn decode(
    string: Option<String>,
    file: Option<String>,
    output: Option<String>,
) -> anyhow::Result<()> {
    // clap has ensured that only `string` or `file` is `Some` but not both
    let decoded = match (string, file) {
        (Some(string), _) => base64_decode(string),
        (_, Some(path)) => base64_decode(fs::read(path)?),
        (None, None) => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            base64_decode(buf)
        }
    }
    .ok_or_else(|| anyhow!("failed to base64-decode input"))?;

    if let Some(out) = output {
        fs::write(out, decoded)?;
    } else {
        io::stdout().write_all(decoded.as_ref())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn encode_and_decode_string() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("output.txt").as_path().to_str().unwrap().to_string();

        encode(
            Some("hello, world!".to_string()),
            None,
            Some(output.clone()),
        )
        .unwrap();

        // ensure the string has been encoded correctly
        let contents = fs::read_to_string(&output).unwrap();
        assert_eq!(base64_encode("hello, world!"), contents);

        // ensure the string decodes to same input
        let decode_output =
            dir.path().join("decode_output1.txt").as_path().to_str().unwrap().to_string();
        decode(Some(contents), None, Some(decode_output.clone())).unwrap();

        let decoded = fs::read_to_string(decode_output).unwrap();
        assert_eq!(decoded.as_str(), "hello, world!");
    }

    #[test]
    fn encode_and_decode_file() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt").as_path().to_str().unwrap().to_string();
        let output = dir.path().join("output.txt").as_path().to_str().unwrap().to_string();
        fs::write(&input, "goodbye, world!").unwrap();

        encode(None, Some(input), Some(output.clone())).unwrap();

        // ensure the string has been encoded correctly
        let contents = fs::read_to_string(&output).unwrap();
        assert_eq!(base64_encode("goodbye, world!"), contents);

        // ensure the file contents decode to same input
        let decode_output =
            dir.path().join("decode_output1.txt").as_path().to_str().unwrap().to_string();
        decode(None, Some(output), Some(decode_output.clone())).unwrap();

        let decoded = fs::read_to_string(decode_output).unwrap();
        assert_eq!(decoded.as_str(), "goodbye, world!");
    }

    #[test]
    fn encode_file_doesnt_exist() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt").as_path().to_str().unwrap().to_string();
        let output = dir.path().join("output.txt").as_path().to_str().unwrap().to_string();

        assert!(encode(None, Some(input), Some(output.clone())).is_err());
    }

    #[test]
    fn decode_not_base64() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt").as_path().to_str().unwrap().to_string();
        let output = dir.path().join("output.txt").as_path().to_str().unwrap().to_string();
        fs::write(&input, "goodbye, world!").unwrap();

        assert!(decode(
            Some("hello, world!".to_string()),
            None,
            Some(output.clone())
        )
        .is_err());
        assert!(decode(None, Some(input), Some(output.clone())).is_err());
    }
}
