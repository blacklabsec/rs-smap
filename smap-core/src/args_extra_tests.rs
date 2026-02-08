//! Additional comprehensive tests for argument parsing edge cases

#[cfg(test)]
mod additional_tests {
    use crate::args::SmapArgs;

    #[test]
    fn test_combined_flags_not_separated() {
        // Test that we don't accidentally support combined boolean flags like -vd
        // (Nmap doesn't support this, each flag needs to be separate or use long form)
        let result = SmapArgs::from_iter_safe(["smap", "-vd", "192.168.1.1"]);
        // This should fail because "vd" is not a recognized argument
        assert!(result.is_err());
    }

    #[test]
    fn test_port_all_ports_dash() {
        // Test the special case of "-" meaning all ports (65535 ports)
        let args = SmapArgs::from_iter_safe(["smap", "-p", "-", "192.168.1.1"]).unwrap();
        assert_eq!(args.ports, Some("-".to_string()));
        assert_eq!(args.targets, vec!["192.168.1.1"]);
    }

    #[test]
    fn test_port_attached_dash() {
        // Test "-p-" as a single token
        let args = SmapArgs::from_iter_safe(["smap", "-p-", "192.168.1.1"]).unwrap();
        assert_eq!(args.ports, Some("-".to_string()));
    }

    #[test]
    fn test_timing_attached() {
        // Test "-T4" as a single token
        let args = SmapArgs::from_iter_safe(["smap", "-T4", "192.168.1.1"]).unwrap();
        assert_eq!(args.timing_template, Some("4".to_string()));
    }

    #[test]
    fn test_timing_separated() {
        // Test "-T 4" as separate tokens
        let args = SmapArgs::from_iter_safe(["smap", "-T", "4", "192.168.1.1"]).unwrap();
        assert_eq!(args.timing_template, Some("4".to_string()));
    }

    #[test]
    fn test_equals_format() {
        // Test --arg=value format
        let args = SmapArgs::from_iter_safe(["smap", "--top-ports=100", "192.168.1.1"]).unwrap();
        assert_eq!(args.top_ports, Some(100));
    }

    #[test]
    fn test_double_dash_long_form() {
        // Test that long-form arguments work
        let args =
            SmapArgs::from_iter_safe(["smap", "--version-intensity", "7", "192.168.1.1"]).unwrap();
        assert_eq!(args.version_intensity, Some(7));
    }

    #[test]
    fn test_multiple_targets_with_cidr() {
        let args = SmapArgs::from_iter_safe(["smap", "192.168.1.0/24", "10.0.0.1", "example.com"])
            .unwrap();
        assert_eq!(args.targets.len(), 3);
        assert_eq!(args.targets[0], "192.168.1.0/24");
        assert_eq!(args.targets[1], "10.0.0.1");
        assert_eq!(args.targets[2], "example.com");
    }

    #[test]
    fn test_flags_before_and_after_target() {
        // Nmap allows flags anywhere in the command
        let args =
            SmapArgs::from_iter_safe(["smap", "-sS", "192.168.1.1", "-v", "10.0.0.1", "-p", "80"])
                .unwrap();
        assert!(args.syn_scan);
        assert!(args.verbose);
        assert_eq!(args.ports, Some("80".to_string()));
        assert_eq!(args.targets.len(), 2);
    }

    #[test]
    fn test_numeric_intensity_parsing() {
        // Test various numeric parsing
        let args = SmapArgs::from_iter_safe([
            "smap",
            "--min-rate",
            "100.5",
            "--max-rate",
            "1000",
            "192.168.1.1",
        ])
        .unwrap();
        assert_eq!(args.min_rate, Some(100.5));
        assert_eq!(args.max_rate, Some(1000.0));
    }

    #[test]
    fn test_path_arguments() {
        // Test file path arguments
        let args = SmapArgs::from_iter_safe([
            "smap",
            "-iL",
            "/path/to/targets.txt",
            "-oX",
            "/tmp/output.xml",
            "--excludefile",
            "/path/to/exclude.txt",
        ])
        .unwrap();
        assert_eq!(
            args.input_list.unwrap().to_str().unwrap(),
            "/path/to/targets.txt"
        );
        assert_eq!(
            args.output_xml.unwrap().to_str().unwrap(),
            "/tmp/output.xml"
        );
        assert_eq!(
            args.exclude_file.unwrap().to_str().unwrap(),
            "/path/to/exclude.txt"
        );
    }

    #[test]
    fn test_iflist_without_targets() {
        // --iflist should work without targets
        let args = SmapArgs::from_iter_safe(["smap", "--iflist"]).unwrap();
        assert!(args.iflist);
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_all_boolean_flags() {
        // Test that all boolean flags don't require values
        let flags = vec![
            "-sL", "-sn", "-Pn", "-PS", "-PA", "-PU", "-PE", "-n", "-R", "-sS", "-sT", "-sA",
            "-sU", "-sN", "-sF", "-sX", "-sV", "-sC", "-O", "-f", "-v", "-d", "-6", "-A", "-F",
            "-r",
        ];

        for flag in flags {
            let result = SmapArgs::from_iter_safe(["smap", flag, "192.168.1.1"]);
            assert!(result.is_ok(), "Flag {} should parse successfully", flag);
        }
    }

    #[test]
    fn test_port_specification_formats() {
        // Test various port specification formats
        let test_cases = vec![
            ("80", "80"),
            ("80,443", "80,443"),
            ("1-1000", "1-1000"),
            ("80,443,8080-8090", "80,443,8080-8090"),
            ("T:80,U:53", "T:80,U:53"), // TCP and UDP port specification
            ("-", "-"),                 // All ports
        ];

        for (input, expected) in test_cases {
            let args = SmapArgs::from_iter_safe(["smap", "-p", input, "192.168.1.1"]).unwrap();
            assert_eq!(
                args.ports,
                Some(expected.to_string()),
                "Port spec {} should be parsed as {}",
                input,
                expected
            );
        }
    }

    #[test]
    fn test_invalid_numeric_values() {
        // Test that invalid numeric values are caught
        let result =
            SmapArgs::from_iter_safe(["smap", "--top-ports", "not_a_number", "192.168.1.1"]);
        assert!(result.is_err());

        let result =
            SmapArgs::from_iter_safe(["smap", "--version-intensity", "abc", "192.168.1.1"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_string_target() {
        // Test that empty strings are handled
        let args = SmapArgs::from_iter_safe(["smap", ""]).unwrap();
        assert_eq!(args.targets, vec![""]);
    }

    #[test]
    fn test_aggressive_mode_sets_flag() {
        // -A should enable aggressive mode
        let args = SmapArgs::from_iter_safe(["smap", "-A", "192.168.1.1"]).unwrap();
        assert!(args.aggressive);
    }

    #[test]
    fn test_script_related_flags() {
        let args =
            SmapArgs::from_iter_safe(["smap", "-sC", "--script", "--script-trace", "192.168.1.1"])
                .unwrap();
        assert!(args.default_scripts);
        assert!(args.script);
        assert!(args.script_trace);
    }
}
