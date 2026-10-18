from globalban.privacy.masking import mask_ip


def test_mask_ipv4_to_24():
    assert mask_ip("192.0.2.42") == "192.0.2.0/24"


def test_mask_ipv6_to_64():
    assert mask_ip("2001:db8:abcd:12::42") == "2001:db8:abcd:12::/64"
