import "pe"

rule kat_pe
{
    condition:
        pe.is_pe
}
