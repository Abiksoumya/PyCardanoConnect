from core.mod import C
from typing import Optional
import binascii





class Utils:
    def __init__(self,lucid):
        self.lucid = lucid

    def validator_to_address(self, validator, stake_credential=None):
        validator_hash = self.validator_to_scriptHash(validator)

        if stake_credential:
            return C.BaseAddress.new(self.lucid.network,
                    C.StakeCredential.from_scripthash(C.ScriptHash.from_hex(validator_hash)),
                    C.StakeCredential.from_keyhash(
                    C.Ed25519KeyHash.from_hex(stake_credential.hash)
                                    )
                    if stake_credential.type == "Key"
                    else C.StakeCredential.from_scripthash(
                    C.ScriptHash.from_hex(stake_credential.hash)
                                    ),

                    ).to_address().to_bech32(None)
        else:
            return C.EnterpriseAddress.new(
                self.lucid.network,  # Replace with appropriate network ID
                C.StakeCredential.from_scripthash(C.ScriptHash.from_hex(validator_hash)),
            ).to_address().to_bech32(None)
                                     
                                     







def fromHex(hex_string: str) -> bytes:
    return bytes.fromhex(hex_string)

def toHex(byte_array: bytes) -> str:
    return binascii.hexlify(byte_array).decode('utf-8')

# Address from Hex
def addressFromHexOrBech32(address: str) -> C.Address:
    try:
        return C.Address.from_bytes(fromHex(address))
    except:
        try:
            return C.Address.from_bech32(address)
        except:
            raise Exception("Could not deserialize address.")




# address can be in Bech32 or Hex 

class Credential:

    def __init__(self,type:str, hash:str):
        self.type = type
        self.hash = hash

class Address_details:
    def __init__(self, type: str, networkId: int, address: dict, paymentCredential: Credential, stakeCredential: Credential):
        self.type = type
        self.networkId = networkId
        self.address = address
        self.paymentCredential = paymentCredential
        self.stakeCredential = stakeCredential

def getAddressDetails(address: str) -> Optional[Address_details]:
    try:
        parsedAddress = C.BaseAddress.from_address(addressFromHexOrBech32(address))
        payment_cred_kind = parsedAddress.payment_cred().kind()
        paymentCredential = Credential("Key", toHex(parsedAddress.payment_cred().to_keyhash().to_bytes())) if payment_cred_kind == 0 else Credential("Script", toHex(parsedAddress.payment_cred().to_scripthash().to_bytes()))
        stake_cred_kind = parsedAddress.stake_cred().kind()
        stakeCredential = Credential("Key", toHex(parsedAddress.stake_cred().to_keyhash().to_bytes())) if stake_cred_kind == 0 else Credential("Script", toHex(parsedAddress.stake_cred().to_scripthash().to_bytes()))
        return Address_details(
            "Base",
            parsedAddress.to_address().network_id(),
            {
                "bech32": parsedAddress.to_address().to_bech32(None),
                "hex": toHex(parsedAddress.to_address().to_bytes())
            },
            paymentCredential,
            stakeCredential
        )
    except:
        pass


