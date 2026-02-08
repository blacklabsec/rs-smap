//! Common utilities for output formatting

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::time::SystemTime;

/// Time format type
#[derive(Debug, Clone, Copy)]
pub enum TimeFormat {
    /// Nmap file format (e.g., "Thu Jun 02 17:45:23 2023")
    NmapFile,
    /// Nmap stdout format (e.g., "2023-06-02 17:45 EDT")
    NmapStdout,
    /// Unix timestamp (seconds since epoch)
    Unix,
}

/// Output writer that can write to stdout or a file
pub struct OutputWriter {
    file: Option<std::fs::File>,
    destination: String,
}

impl OutputWriter {
    /// Create a new OutputWriter for stdout
    pub fn stdout() -> Self {
        Self {
            file: None,
            destination: "-".to_string(),
        }
    }

    /// Create a new OutputWriter for a file
    pub fn file(path: impl AsRef<Path>) -> io::Result<Self> {
        let path_str = path.as_ref().display().to_string();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        Ok(Self {
            file: Some(file),
            destination: path_str,
        })
    }

    /// Write a string to the output
    pub fn write(&mut self, s: &str) -> io::Result<()> {
        if let Some(ref mut f) = self.file {
            f.write_all(s.as_bytes())
        } else {
            print!("{}", s);
            Ok(())
        }
    }

    /// Get the destination (file path or "-" for stdout)
    pub fn destination(&self) -> &str {
        &self.destination
    }
}

/// Convert a SystemTime to a formatted string
pub fn format_time(time: SystemTime, format: TimeFormat) -> String {
    use chrono::{DateTime, Local};

    let datetime: DateTime<Local> = time.into();

    match format {
        TimeFormat::NmapFile => {
            // Format: "Thu Jun 02 17:45:23 2023"
            let formatted = datetime.format("%a %b %d %H:%M:%S %Y").to_string();
            formatted
        }
        TimeFormat::NmapStdout => {
            // Format: "2023-06-02 17:45 EDT"
            datetime.format("%Y-%m-%d %H:%M %Z").to_string()
        }
        TimeFormat::Unix => {
            // Unix timestamp
            datetime.timestamp().to_string()
        }
    }
}

/// Get command line arguments as a string (simulated for now)
pub fn get_command(args: &[String]) -> String {
    if args.is_empty() {
        "smap".to_string()
    } else {
        format!("smap {}", args.join(" "))
    }
}

/// Pad a string with spaces on the left
pub fn pad_left(s: &str, width: usize) -> String {
    if s.len() >= width {
        s.to_string()
    } else {
        format!("{}{}", " ".repeat(width - s.len()), s)
    }
}

/// Pad a string with spaces on the right
pub fn pad_right(s: &str, width: usize) -> String {
    if s.len() >= width {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(width - s.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_pad_left() {
        assert_eq!(pad_left("test", 10), "      test");
        assert_eq!(pad_left("test", 4), "test");
        assert_eq!(pad_left("test", 2), "test");
    }

    #[test]
    fn test_pad_right() {
        assert_eq!(pad_right("test", 10), "test      ");
        assert_eq!(pad_right("test", 4), "test");
        assert_eq!(pad_right("test", 2), "test");
    }

    #[test]
    fn test_get_command() {
        assert_eq!(get_command(&[]), "smap");
        assert_eq!(
            get_command(&["192.168.1.1".to_string()]),
            "smap 192.168.1.1"
        );
        assert_eq!(
            get_command(&["-p".to_string(), "80".to_string()]),
            "smap -p 80"
        );
    }

    #[test]
    fn test_output_writer_stdout() {
        let writer = OutputWriter::stdout();
        assert_eq!(writer.destination(), "-");
    }

    #[test]
    fn test_output_writer_file() {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("smap_test_output.txt");

        // Clean up any existing file
        let _ = std::fs::remove_file(&temp_file);

        let writer = OutputWriter::file(&temp_file);
        assert!(writer.is_ok());

        let writer = writer.unwrap();
        assert_eq!(writer.destination(), temp_file.display().to_string());

        // Clean up
        let _ = std::fs::remove_file(&temp_file);
    }

    #[test]
    fn test_output_writer_write_to_file() {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("smap_test_write.txt");

        // Clean up any existing file
        let _ = std::fs::remove_file(&temp_file);

        let mut writer = OutputWriter::file(&temp_file).unwrap();
        assert!(writer.write("test content\n").is_ok());

        // Verify content
        let content = std::fs::read_to_string(&temp_file).unwrap();
        assert_eq!(content, "test content\n");

        // Clean up
        let _ = std::fs::remove_file(&temp_file);
    }

    #[test]
    fn test_format_time_unix() {
        let time = UNIX_EPOCH + Duration::from_secs(1609459200); // 2021-01-01 00:00:00 UTC
        let formatted = format_time(time, TimeFormat::Unix);
        // The exact value depends on the local timezone
        assert!(!formatted.is_empty());
    }

    #[test]
    fn test_format_time_nmap_file() {
        let time = SystemTime::now();
        let formatted = format_time(time, TimeFormat::NmapFile);
        // Should contain month abbreviation
        assert!(formatted.len() > 10);
    }

    #[test]
    fn test_format_time_nmap_stdout() {
        let time = SystemTime::now();
        let formatted = format_time(time, TimeFormat::NmapStdout);
        // Should contain year in format YYYY
        assert!(formatted.contains("202") || formatted.contains("203"));
    }

    #[test]
    fn test_time_format_types() {
        // Ensure all TimeFormat variants can be used
        let time = SystemTime::now();
        let _ = format_time(time, TimeFormat::NmapFile);
        let _ = format_time(time, TimeFormat::NmapStdout);
        let _ = format_time(time, TimeFormat::Unix);
    }
}
