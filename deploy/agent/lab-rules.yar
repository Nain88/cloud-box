// A harmless demonstration marker. This is not a malware detection ruleset.
rule CBB_Lab_Marker {
    meta:
        description = "Detects an explicit Cyber Black Box laboratory marker"
        revision = "1"
    strings:
        $marker = "CBB_TEST_MARKER" ascii
    condition:
        $marker
}
