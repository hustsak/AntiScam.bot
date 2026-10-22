rule KhmerShield_Test_Suspicious_Pattern
{
    meta:
        description = "Safe KhmerShield test rule"
        author = "KhmerShield-AI"
        severity = "medium"

    strings:
        $test1 = "KHMER_SHIELD_TEST"
        $test2 = "SUSPICIOUS_TEST_PATTERN"

    condition:
        any of them
}