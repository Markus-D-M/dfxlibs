=====
Cached Domain Credentials
=====

Reference Urls:
 - https://joshmoulin.com/domain-vs-local-accounts-in-the-windows-registry/
 - https://github.com/moyix/creddump
 - https://www.passcape.com/index.php?section=docsys&cmd=details&id=23
 - https://github.com/skelsec/pypykatz/blob/master/pypykatz/registry/security/asecurity.py


Needed Registry Keys
    Number of cached credentials
        - HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\CachedLogonsCount
    Cached Credentials
        - HKLM\\SECURITY\\Cache\\
    Boot Key Information (from Key Classname)
        - HKLM\\SYSTEM\ControlSet00X\\Control\\Lsa\\JD\\
        - HKLM\\SYSTEM\ControlSet00X\\Control\\Lsa\\Skew1\\
        - HKLM\\SYSTEM\ControlSet00X\\Control\\Lsa\\GBG\\
        - HKLM\\SYSTEM\ControlSet00X\\Control\\Lsa\\Data\\
    LSA Key
        - HKLM\SECURITY\Policy\PolEKList\ (was HKLM\SECURITY\Policy\PolSecretEncryptionKey before Vista)
    NL$KM Key
        - HKLM\SECURITY\Policy\Secrets\NL$KM\CurrVal\

Calculate Needed Keys
    Bootkey
        - bootkey_perm_matrix = [ 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 ]
        - bootkey_scrambled = (JD_Classname + Skew1_Classname + GBG_Classname + Data_Classname).decode('hex')
        - bootkey = join([bootkey_scrambled[bootkey_perm_matrix[i]] for i in range(len(bootkey_scrambled))])

    LSAkey
        - rc4_key = md5(bootkey + 1000*PolSecretEncryptionKey[60:76]).digest()
        - lsa_key = RC4(rc4_key).decrypt(PolSecretEncryptionKey[12:60])[0x10:0x20]

    NL$KMkey
        - enc_key = NLLM_CurrVal[0x0c:]
