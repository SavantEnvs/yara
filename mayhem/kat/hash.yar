import "hash"

rule kat_md5
{
    condition:
        hash.md5(0, filesize) == "665482ae10d09d5fd283557b7979acd0"
}

rule kat_sha256
{
    condition:
        hash.sha256(0, filesize) == "c704cca0fe4c9bdee18a302952540073b860e3b4d42e081f86d27bdb1cf6ede4"
}

rule kat_wrong_md5
{
    condition:
        hash.md5(0, filesize) == "00000000000000000000000000000000"
}
