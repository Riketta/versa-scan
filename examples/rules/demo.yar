// Demo rule set for the `yara-x` scanner.
//
// Point `[yara_x] rules_path` at this directory (or any *.yar/*.yara file)
// and run `vscli submit --scanner yara-x --wait sample.txt`.
//
// Deliberately no EICAR string here: Windows Defender real-time protection
// quarantines files containing it on sight, which would make the sample
// unfetchable/scannable on a Windows worker.

rule vs_demo_marker
{
    meta:
        description = "Detects the versa-scan demo marker"
        author = "versa-scan"
        reference = "https://example.test/vs-demo"
    strings:
        $marker = "VS-YARA-DEMO-MARKER-42"
    condition:
        $marker
}

rule vs_pe_with_high_entropy_section
{
    meta:
        description = "Example structural rule sketch (PE module)"
    condition:
        false // placeholder: extend with real logic, e.g. pe.is_pe and math
}
