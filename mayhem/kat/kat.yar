rule kat_two_hellos
{
    meta:
        author = "kat"
    strings:
        $a = "hello"
    condition:
        #a == 2
}

rule kat_no_goodbye
{
    strings:
        $a = "goodbye"
    condition:
        $a
}
