import six

from cryptography import utils
from cryptography.x509.name import _ASN1Type, _SENTINEL
from cryptography.x509.oid import ObjectIdentifier, AttributeOID

_ATTRIBUTEOID_DEFAULT_TYPE = {
    AttributeOID.CHALLENGE_PASSWORD: _ASN1Type.PrintableString,
}


class Attribute(object):
    def __init__(self, oid, value, _type=_SENTINEL):
        if not isinstance(oid, ObjectIdentifier):
            raise TypeError(
                "oid argument must be an ObjectIdentifier instance."
            )

        if not isinstance(value, six.text_type):
            raise TypeError(
                "value argument must be a text type."
            )

        if len(value) == 0:
            raise ValueError("Value cannot be an empty string")

        if _type == _SENTINEL:
            _type = _ATTRIBUTEOID_DEFAULT_TYPE.get(oid, _ASN1Type.UTF8String)

        if not isinstance(_type, _ASN1Type):
            raise TypeError("_type must be from the _ASN1Type enum")

        self._oid = oid
        self._value = value
        self._type = _type

    oid = utils.read_only_property("_oid")
    value = utils.read_only_property("_value")

    def __repr__(self):
        return ("<Attribute(oid={0.oid}, value={0.value})>").format(self)

    def __eq__(self, other):
        if not isinstance(other, Attribute):
            return NotImplemented

        return (
                self.oid == other.oid and
                self.value == other.value
        )

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.oid, self.value))
