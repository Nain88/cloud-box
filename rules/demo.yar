rule CBB_Benign_Demonstration_Marker {
    meta:
        description = "Safe test rule. A match is not a malware verdict."
        version = "1.0"
    strings:
        $marker = "CBB-BENIGN-TEST-MARKER"
    condition:
        $marker
}
